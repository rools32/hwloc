# Copyright © 2017      Inria.  All rights reserved.
#
# See COPYING in top-level directory.
#
# $HEADER$
#

noinst_LTLIBRARIES = \
	libnetloc_topo_explicit.la

AM_CPPFLAGS = \
        -I$(top_builddir)/include \
        -I$(top_srcdir)/include

libnetloc_topo_explicit_la_SOURCES = \
    netloc_topo_explicit.c \
	netloc_topo_utils_to_netloc.c

libnetloc_topo_explicit_la_LIBADD = \
	$(top_builddir)/utils/netloc/export/xml/libnetloc_xml_export.la
