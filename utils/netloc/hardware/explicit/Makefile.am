# Copyright © 2017 Inria.  All rights reserved.
#
# See COPYING in top-level directory.
#
# $HEADER$
#
AM_CPPFLAGS = \
        -I$(top_builddir)/include \
        -I$(top_srcdir)/include

LDADD = \
	$(top_builddir)/netloc/libnetloc.la \
	$(top_builddir)/hwloc/libhwloc.la

if BUILD_MPITOOLS
bin_PROGRAMS = netloc_explicit_find_hosts
endif

netloc_explicit_find_hosts_SOURCES = netloc_explicit_find_hosts.c
netloc_explicit_find_hosts_CPPFLAGS = $(AM_CPPFLAGS) $(MPI_CPPFLAGS)
netloc_explicit_find_hosts_LDADD = $(LDADD) $(MPI_LDADD)
