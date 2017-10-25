# Copyright © 2013      Cisco Systems, Inc.  All rights reserved.
# Copyright © 2013      University of Wisconsin-La Crosse.
#                       All rights reserved.
# Copyright © 2015-2017 Inria.  All rights reserved.
#
# See COPYING in top-level directory.
#
# $HEADER$
#
bin_SCRIPTS = \
        netloc_ib_gather_raw
CLEANFILES = $(bin_SCRIPTS)

install-exec-hook:
	chmod +x $(DESTDIR)$(bindir)/netloc_ib_gather_raw

AM_CPPFLAGS = \
        -I$(top_builddir)/include \
        -I$(top_srcdir)/include

bin_PROGRAMS = \
        netloc_ib_extract_dats

netloc_ib_extract_dats_SOURCES = \
        netloc_ib_extract_dats.c

netloc_ib_extract_dats_LDADD = \
	$(top_builddir)/netloc/libnetloc.la \
	$(top_builddir)/utils/netloc/topology/explicit/libnetloc_topo_explicit.la
