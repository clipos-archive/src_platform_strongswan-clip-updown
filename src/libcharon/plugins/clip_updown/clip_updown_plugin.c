// SPDX-License-Identifier: GPL-2.0
// Copyright © 2012-2018 ANSSI. All Rights Reserved.
/*
 * Copyright (C) 2012 SGDSN/ANSSI
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

#include "clip_updown_plugin.h"
#include "clip_updown_listener.h"

#include <daemon.h>

typedef struct private_clip_updown_plugin_t private_clip_updown_plugin_t;

/**
 * private data of updown plugin
 */
struct private_clip_updown_plugin_t {

	/**
	 * implements plugin interface
	 */
	clip_updown_plugin_t public;

	/**
	 * Listener interface, listens to CHILD_SA state changes
	 */
	clip_updown_listener_t *listener;
};

METHOD(plugin_t, get_name, char*,
	private_clip_updown_plugin_t *this)
{
	return "clip_updown";
}

/**
 * Register listener
 */
static bool 
plugin_cb(private_clip_updown_plugin_t *this,
	plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		this->listener = clip_updown_listener_create();
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
		this->listener->destroy(this->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_clip_updown_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "clip_updown"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_clip_updown_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *clip_updown_plugin_create()
{
	private_clip_updown_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}

