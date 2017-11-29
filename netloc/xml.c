/* -*- encoding: utf-8 -*- */
/*
 * Copyright © 2017      Inria.  All rights reserved.
 *
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 * See COPYING in top-level directory.
 *
 * $HEADER$
 */

#define _GNU_SOURCE	   /* See feature_test_macros(7) */

#include <stdlib.h>

#include <private/autogen/config.h>
#include <private/netloc.h>
#include <private/netloc-xml.h>

#if defined(HWLOC_HAVE_LIBXML2)
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

extern int
netloc_network_explicit_libxml_load(const char *path,
                                    netloc_network_explicit_t **ptopology);

#else

extern int
netloc_network_explicit_nolibxml_load(const char *path,
                                      netloc_network_explicit_t **ptopology);

#endif /* defined(HWLOC_HAVE_LIBXML2) */

int netloc__xml_verbose(void)
{
  static int checked = 0;
#ifdef NETLOC_DEBUG
  static int verbose = 1;
#else
  static int verbose = 0;
#endif
  if (!checked) {
    const char *env = getenv("HWLOC_XML_VERBOSE");
    if (env)
      verbose = atoi(env);
    checked = 1;
  }
  return verbose;
}

#if defined(HWLOC_HAVE_LIBXML2)

int netloc_network_explicit_xml_load(const char *path,
                                     netloc_network_explicit_t **ptopology)
{
    return netloc_network_explicit_libxml_load(path, ptopology);
}

#else

int netloc_network_explicit_xml_load(const char *path,
                                     netloc_network_explicit_t **ptopology)
{
    return netloc_network_explicit_nolibxml_load(path, ptopology);
}

#endif /* defined(HWLOC_HAVE_LIBXML2) */
