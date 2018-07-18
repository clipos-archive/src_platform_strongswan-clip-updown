# SPDX-License-Identifier: GPL-2.0
# Copyright © 2012-2018 ANSSI. All Rights Reserved.

INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if USE_CCSD
INCLUDES += -I /usr/include/ccsd-3.3 -I $(top_srcdir)/src/include
AM_CFLAGS += -DUNIX
endif

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-clip-updown.la
else
plugin_LTLIBRARIES = libstrongswan-clip-updown.la
endif

libstrongswan_clip_updown_la_SOURCES = \
	clip_updown_plugin.h clip_updown_plugin.c \
	clip_updown_listener.h clip_updown_listener.c

libstrongswan_clip_updown_la_LDFLAGS = -module -avoid-version
