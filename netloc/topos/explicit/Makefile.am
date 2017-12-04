#
# Copyright © 2017      Inria.  All rights reserved.
#
# See COPYING in top-level directory.
#
# $HEADER$
#

noinst_LTLIBRARIES = \
	libnetloc_topos_explicit.la

AM_CPPFLAGS = \
        -I$(top_builddir)/include \
        -I$(top_srcdir)/include

sources = \
	network_explicit.c \
    node.c \
	edge.c \
	physical_link.c

libnetloc_topos_explicit_la_SOURCES = $(sources)
libnetloc_topos_explicit_la_LDFLAGS = $(ldflags) --version-info
libnetloc_topos_explicit_la_LIBADD = \
        $(top_builddir)/hwloc/libhwloc.la
