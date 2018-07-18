// SPDX-License-Identifier: GPL-2.0
// Copyright © 2012-2018 ANSSI. All Rights Reserved.
/*
 * Copyright (C) 2012-2013 SGDSN/ANSSI
 * Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Based on the original strongswan updown plugin, which is :
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

#include "clip_updown_listener.h"

#include <hydra.h>
#include <daemon.h>
#include <config/child_cfg.h>

#define DAEMON_CMD	"/sbin/ipsec-updownd"

#define _WARN(fmt, args...) \
	charon->bus->log(charon->bus, DBG_CHD, LEVEL_AUDIT, \
			"%s() (%s:%d): "fmt, __FUNCTION__, \
			__FILE__, __LINE__, ##args)

#define LOG(fmt, args...) \
	charon->bus->log(charon->bus, DBG_CHD, LEVEL_AUDIT, \
			"%s() (%s:%d): "fmt, __FUNCTION__, \
			__FILE__, __LINE__, ##args)

#define DEBUG(fmt, args...) \
	charon->bus->log(charon->bus, DBG_CHD, LEVEL_CTRL, \
			"%s() (%s:%d): "fmt, __FUNCTION__, \
			__FILE__, __LINE__, ##args)

#define WARN(fmt, args...) _WARN(fmt, ##args)
#define WARN_ERRNO(fmt, args...) _WARN(fmt": %s", ##args, strerror(errno))


typedef struct private_clip_updown_listener_t private_clip_updown_listener_t;

/**
 * Private data of a clip_updown_listener_t object.
 */
struct private_clip_updown_listener_t {

	/**
	 * Public clip_updown_listener_t interface.
	 */
	clip_updown_listener_t public;

	/**
	 * Socket to communicate with updown daemon.
	 */
	int socket;


	/**
	 * Daemon pid.
	 */
	pid_t pid;

	/**
	 * List of cached interface names
	 */
	linked_list_t *iface_cache;
};

#define MAGIC_STRING	"CLIP-UPD-1.0"

struct ipsec_updown_msg {
	char magic[16];		/* Magic / version string */
	char action[8];		/* "up" or "down" */
	char config[32];	/* Config name */
	char type[8];		/* "host" or "client" */
	char iface[32];		/* Interface name or "unknown" */
	char my_id[128];	/* My ID */
	char peer_id[128];	/* Remote ID */
	char vip[16];		/* Virtual IP, e.g. "192.168.123.231" */
} __attribute__((packed));

typedef struct ipsec_updown_msg ipsec_updown_msg_t;


typedef struct cache_entry_t cache_entry_t;

/**
 * Cache line in the interface name cache.
 */
struct cache_entry_t {
	/** requid of the CHILD_SA */
	u_int32_t reqid;
	/** cached interface name */
	char *iface;
};

/**
 * Insert an interface name to the cache
 */
static void cache_iface(private_clip_updown_listener_t *this, u_int32_t reqid,
						char *iface)
{
	cache_entry_t *entry = malloc_thing(cache_entry_t);

	if (!entry) {
		WARN("Failed to cache entry - out of memory");
		return;
	}

	entry->reqid = reqid;
	entry->iface = strdup(iface);
	if (!entry->iface) {
		WARN("Failed to duplicate iface for cache entry - out of memory");
		free(entry);
		return;
	}

	this->iface_cache->insert_first(this->iface_cache, entry);
}

/**
 * Remove a cached interface name and return it.
 */
static char* uncache_iface(private_clip_updown_listener_t *this, u_int32_t reqid)
{
	enumerator_t *enumerator;
	cache_entry_t *entry;
	char *iface = NULL;

	enumerator = this->iface_cache->create_enumerator(this->iface_cache);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->reqid == reqid)
		{
			this->iface_cache->remove_at(this->iface_cache, enumerator);
			iface = entry->iface;
			free(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return iface;
}

static inline char *
get_first_virtual_ip(ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	host_t *host;
	char buf[16];

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);

	while (enumerator->enumerate(enumerator, &host))
	{
		if (host->get_family(host) == AF_INET)
		{
			if ((unsigned)snprintf(buf, sizeof(buf), "%H", host) 
							>= sizeof(buf)) {
				WARN("Too long for an IPv4 : %H", host);
				continue;
			}
			enumerator->destroy(enumerator);
			return strdup(buf);
		}
	}
		
	enumerator->destroy(enumerator);
	return NULL;
}

static inline ipsec_updown_msg_t * 
create_msg(private_clip_updown_listener_t *this, 
	const char *config, bool up, 
	ike_sa_t *ike_sa, child_sa_t *child_sa, 
	traffic_selector_t *my_ts, 
	traffic_selector_t *other_ts __attribute__((unused)), 
	host_t *me, host_t *other __attribute__((unused)))
{
	ipsec_updown_msg_t *msg;
	char *iface = NULL;
	char *vip = NULL;

	msg = malloc_thing(ipsec_updown_msg_t);
	if (!msg) {
		WARN("Out of memory allocating ipsec_updown_msg_t");
		return NULL;
	}
	memset(msg, 0, sizeof(*msg));

	memcpy(msg->magic, MAGIC_STRING, sizeof(MAGIC_STRING));

#define copy_field(field, src, fmt) do {\
	if ((unsigned)snprintf(msg->field, sizeof(msg->field), fmt, src) >= sizeof(msg->field)) \
	{\
		WARN("Truncated " #field "field: "fmt, src); \
		goto err; \
	} \
} while (0)

	vip = get_first_virtual_ip(ike_sa);

	if (vip) {
		copy_field(vip, vip, "%s");
		free(vip);
	} else 
		copy_field(vip, "none", "%s");

	if (up)
	{
		if (hydra->kernel_interface->get_interface(hydra->kernel_interface, me, &iface))
		{
			cache_iface(this, child_sa->get_reqid(child_sa), iface);
		}
	}
	else
	{
		iface = uncache_iface(this, child_sa->get_reqid(child_sa));
	}
	if (iface) 
		copy_field(iface, iface, "%s");

	if (config)
		copy_field(config, config, "%s");

	if (up)
		memcpy(msg->action, "up", sizeof("up"));
	else
		memcpy(msg->action, "down", sizeof("down"));

	
	if (my_ts->is_host(my_ts, me))
		memcpy(msg->type, "host", sizeof("host"));
	else
		memcpy(msg->type, "client", sizeof("client"));
	
	copy_field(my_id, ike_sa->get_my_id(ike_sa), "%Y");
	copy_field(peer_id, ike_sa->get_other_id(ike_sa), "%Y");

	return msg;

err:
	free(msg);
	return NULL;

#undef copy_field
}

static bool call_daemon(int socket, const ipsec_updown_msg_t *msg)
{
	size_t len = sizeof(*msg);
	char *ptr = (char *)msg;
	ssize_t ret;

	char c;

	while (len > 0) 
	{
		ret = write(socket, ptr, len);
		if (len < 0)
		{
			if (errno == EINTR)
				continue;

			WARN_ERRNO("Failed to send message to daemon");
			return FALSE;
		}

		ptr += ret;
		len -= ret;
	}

	for (;;) 
	{
		ret = read(socket, &c, 1);
		if (ret < 0)
		{
			if (errno == EINTR)
				continue;
			WARN_ERRNO("Failed to read reply from daemon");
			return FALSE;
		}

		if (!ret)
		{
			WARN("Child daemon seems to have exited?");
			return FALSE; /* Next write will probably kill us... */
		}
		
		return (c == 'Y') ? TRUE : FALSE;
	}
}

METHOD(listener_t, child_updown, bool,
	private_clip_updown_listener_t *this, ike_sa_t *ike_sa, 
	child_sa_t *child_sa, bool up)
{
	traffic_selector_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	child_cfg_t *config;
	host_t *me, *other;
	char *script;

	config = child_sa->get_config(child_sa);
	script = config->get_updown(config);
	me = ike_sa->get_my_host(ike_sa);
	other = ike_sa->get_other_host(ike_sa);

	if (script == NULL)
	{
		return TRUE;
	}

	ipsec_updown_msg_t *msg = NULL;

	enumerator = child_sa->create_policy_enumerator(child_sa);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		msg = create_msg(this, config->get_name(config), up, 
					ike_sa, child_sa, 
					my_ts, other_ts, me, other);
		
		if (!msg) 
			goto out;

		if (!call_daemon(this->socket, msg))
			WARN("Updown daemon call returned false");

	}
	/* Fall through */
out:
	if (msg)
		free(msg);
	enumerator->destroy(enumerator);
	/* Note : returning false here does not prevent the child SA
	 * from being created (if up == true), but rather makes charon
	 * remove this listener - which won't get called for further
	 * updates (yes, sounds pretty stupid to me too).
	 * In short : we want to return TRUE here, regardless of the
	 * result of the call to the updown daemon.
	 */
	return TRUE; 
}

METHOD(clip_updown_listener_t, destroy, void,
	private_clip_updown_listener_t *this)
{
	this->iface_cache->destroy(this->iface_cache);
	if (this->socket != -1)
		close(this->socket);
	if (this->pid)
		kill(this->pid, SIGTERM);
	free(this);
}

static bool run_daemon(private_clip_updown_listener_t *this)
{
	int socks[2]; /* 0: father, 1: son */
	char buf[8];
	ssize_t ret;
	pid_t pid; /* Not the actual pid of the daemon, 
		      since it will probably fork itself... */

	memset(buf, 0, sizeof(buf));

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, socks) < 0) 
	{
		WARN_ERRNO("Failed to create socketpair");
		return FALSE;
	}

	pid = fork();
	switch (pid) 
	{
		case -1:
			WARN_ERRNO("Failed to fork updown daemon");
			goto err;
		case 0:
			snprintf(buf, sizeof(buf), "%d", socks[1]);
			(void)close(socks[0]);
			if (execl(DAEMON_CMD, DAEMON_CMD, "-c", buf, NULL) < 0)
			{
				WARN_ERRNO("Failed to execute updown daemon");
				exit(1);
			}
		default:
			(void)close(socks[1]);
			this->socket = socks[0];
			/* Wait for the daemon to start, get its actual pid. */
			for (;;) 
			{
				ret = read(socks[0], buf, sizeof(buf));
				if (ret < 0) 
				{
					if (errno == EINTR)
						continue;
					WARN_ERRNO("Failed to read updown daemon pid");
					goto err;
				}
				if (ret != sizeof(buf)) 
				{
					WARN("Truncated pid read: %zd bytes read", ret);
					goto err;
				}
				break;
			}
			if (buf[sizeof(buf) -1] != 0) 
			{
				WARN("Truncated pid ?? : %.*s", sizeof(buf), buf);
				goto err;
			}
			this->pid = atoi(buf);
			if (!this->pid) 
			{
				WARN_ERRNO("Invalid updown daemon pid");
				goto err;
			}
			/* Reap intermediary daemon process */
			for (;;) {
				int status;
				pid_t wret = waitpid(pid, &status, WNOHANG);
				if (wret < 0) {
					if (errno == EINTR)
						continue;
					break;
				}
				if (wret == pid)
					break;
			}

			return TRUE;
	}
	/* Not reached */
err:
	(void)close(socks[0]);
	(void)close(socks[1]);
	return FALSE;

}

/**
 * See header
 */
clip_updown_listener_t *clip_updown_listener_create()
{
	private_clip_updown_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.child_updown = _child_updown,
			},
			.destroy = _destroy,
		},
		.socket = -1,
		.pid = 0,
		.iface_cache = linked_list_create(),
	);

	if (!run_daemon(this))
	{
		this->public.destroy(&(this->public));
		return NULL;
	}

	return &this->public;
}

