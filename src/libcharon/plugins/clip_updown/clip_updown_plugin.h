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

/**
 * @defgroup clip_updown clip_updown
 * @ingroup cplugins
 *
 * @defgroup clip_updown_plugin clip_updown_plugin
 * @{ @ingroup clip_updown
 */

#ifndef CLIP_UPDOWN_PLUGIN_H_
#define CLIP_UPDOWN_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct clip_updown_plugin_t clip_updown_plugin_t;

/**
 * Updown notification plugin, for use with clip-ipsec-updownd.
 */
struct clip_updown_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** CLIP_UPDOWN_PLUGIN_H_ @}*/
