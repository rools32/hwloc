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

#ifndef _UTILS_XML_H_
#define _UTILS_XML_H_

#include <private/netloc.h>
#include <netloc.h>

#ifdef HWLOC_HAVE_LIBXML2

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

typedef xmlNsPtr xml_ns_ptr;

typedef xmlChar  xml_char;
static inline void xml_char_free(xml_char *s) {
    xmlFree(s);
}
static inline xml_char *xml_char_strdup(const char *s) {
    return xmlCharStrdup(s);
}

typedef xmlNodePtr xml_node_ptr;
static inline xml_node_ptr xml_node_new(xml_ns_ptr ns, const xml_char *n) {
    return xmlNewNode(ns, n);
}
static inline void xml_node_free(xml_node_ptr node) {
    xmlFreeNode(node);
}
static inline void xml_node_attr_add(xml_node_ptr node, const xml_char *name,
                                     const xml_char *value)
{
    (void) xmlNewProp(node, name, value);
}
extern void xml_node_attr_cpy_add(xml_node_ptr pnode, const xml_char *name,
                                  const char *value);
static inline void xml_node_child_add(xml_node_ptr p, xml_node_ptr c) {
    (void) xmlAddChild(p, c);
}
static inline xml_node_ptr xml_node_child_new(xml_node_ptr p, xml_ns_ptr ns,
                                              const xml_char *n,
                                              const xml_char *c)
{
    return xmlNewChild(p, ns, n, c);
}
extern  void xml_node_merge(xml_node_ptr dest, xml_node_ptr src);
static inline int xml_node_has_child(xml_node_ptr node) {
    return (NULL != node->children);
}

typedef xmlDocPtr xml_doc_ptr;
static inline xml_doc_ptr xml_doc_new(const xml_char *version) {
    return xmlNewDoc(version);
}
static inline void xml_doc_free(xml_doc_ptr doc) {
    xmlFreeDoc(doc);
}
static inline xml_node_ptr xml_doc_set_root_element(xml_doc_ptr d,
                                                    xml_node_ptr n)
{
    return xmlDocSetRootElement(d, n);
}
static inline int xml_doc_write(const char *out, xml_doc_ptr d,
                                const char *e, int f)
{
    return xmlSaveFormatFileEnc(out, d, e, f);
}

static inline void xml_dtd_subset_create(xml_doc_ptr doc,
                                         const xml_char *name,
                                         const xml_char *externalid,
                                         const xml_char *systemid)
{
    (void) xmlCreateIntSubset(doc, name, externalid, systemid);
}

#define xml_parser_cleanup()                    \
    do {                                        \
        if (getenv("HWLOC_LIBXML_CLEANUP"))     \
            xmlCleanupParser();                 \
    } while (0)

#define XML_LIB_CHECK_VERSION LIBXML_TEST_VERSION

#else

/* XML writing is made with utils/netloc/utils/xml/utils_xml_write.c */

typedef void * xml_ns_ptr;

typedef char xml_char;
#define BAD_CAST (xml_char *)
static inline void xml_char_free(xml_char *s) {
    free(s);
}
static inline xml_char *xml_char_strdup(const char *c) {
    return strdup(c);
}

struct xml_node_t;
typedef struct xml_node_t * xml_node_ptr;

extern xml_node_ptr xml_node_new(xml_ns_ptr ns __netloc_attribute_unused,
                                 const char *type);

extern void xml_node_free(xml_node_ptr node);


extern void xml_node_attr_add(xml_node_ptr node, const xml_char *name,
                              const xml_char *value);

static inline void
xml_node_attr_cpy_add(xml_node_ptr node, const xml_char *name,
                      const char *value)
{
    xml_node_attr_add(node, name, value);
}

extern void xml_node_child_add(xml_node_ptr node, xml_node_ptr child);

extern xml_node_ptr
xml_node_child_new(xml_node_ptr parent,
                   xml_ns_ptr namespace __netloc_attribute_unused,
                   const xml_char *type, const xml_char *content);

extern void xml_node_merge(xml_node_ptr dest, xml_node_ptr src);

extern int xml_node_has_child(xml_node_ptr node);

struct xml_doc_t;
typedef struct xml_doc_t * xml_doc_ptr;

extern xml_doc_ptr xml_doc_new(const xml_char *version);

extern void xml_doc_free(xml_doc_ptr doc);

extern xml_node_ptr xml_doc_set_root_element(xml_doc_ptr doc, xml_node_ptr node);

extern int xml_doc_write(const char *outpath, xml_doc_ptr doc, const char *enc,
                         int format __netloc_attribute_unused);

extern void
xml_dtd_subset_create(xml_doc_ptr doc, const xml_char *name,
                      const xml_char *externalid __netloc_attribute_unused,
                      const xml_char *systemid);

#define xml_parser_cleanup()  do { /* do nothing */ } while (0)
#define XML_LIB_CHECK_VERSION do { /* do nothing */ } while (0)

#endif /* not defined( HWLOC_HAVE_LIBXLM2 ) */

#endif /* _UTILS_XML_H_ */
