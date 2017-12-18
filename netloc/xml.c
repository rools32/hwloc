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
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <libgen.h>

#include <private/autogen/config.h>
#include <private/netloc-xml.h>
#include <private/utils/xml.h>
#include <netloc/utarray.h>
#include <netloc/uthash.h>

#ifndef HWLOC_HAVE_LIBXML2

/******************************************************************************/
/* Function to handle XML tree */
/******************************************************************************/
/* Contents API needed for the xml_node_t */

typedef struct {
    size_t num;
    size_t allocated;
    void **data;
} contents_t;

static void contents_init(contents_t *contents, size_t allocated)
{
    contents->data = (void **) (allocated ?
                                malloc(sizeof(void *[allocated])) : NULL);
    contents->allocated = allocated;
    contents->num = 0;
}

static void contents_add(contents_t *contents, void *data)
{
    if (contents->num == contents->allocated) {
        if (contents->allocated)
        {
            void **new_data = (void **)
                realloc(contents->data, sizeof(void *[2*contents->allocated]));
            if (!new_data)
                    return;
            contents->data = new_data;
            contents->allocated *= 2;
        } else {
            contents->data = (void **) malloc(sizeof(void *[1]));
            if (!contents->data)
                return;
            contents->allocated = 1;
        }
    }
    contents->data[contents->num] = data;
    contents->num += 1;
}

static void contents_merge(contents_t *dest, const contents_t *src)
{
    size_t new_num   = dest->num + src->num;
    size_t new_alloc = 1 < dest->allocated ? dest->allocated : 1;
    while (new_num > new_alloc)
        new_alloc *= 2;
    void **new_data = (void **) realloc(dest->data, sizeof(void *[new_alloc]));
    if (!new_data)
        return;
    memcpy(&new_data[dest->num], src->data, sizeof(void *[src->num]));
    dest->data      = new_data;
    dest->num       = new_num;
    dest->allocated = new_alloc;
}

static void contents_end(contents_t *contents)
{
    free(contents->data);
}

/******************************************************************************/
/* API to manage xml_node_t */
typedef char xml_char;

struct xml_node_t {
    xml_char *name;
    xml_char *content;
    size_t content_size;
    xml_node_ptr parent;
    contents_t attributes;
    contents_t children;
};
typedef struct xml_node_t * xml_node_ptr;

struct xml_doc_t {
    xml_node_ptr root;
    xml_char *xml_version;
    xml_char *doctype;
};
typedef struct xml_doc_t * xml_doc_ptr;

/* Nodes */
xml_node_ptr xml_node_new(xml_ns_ptr ns __netloc_attribute_unused,
                          const char *type)
{
    xml_node_ptr node = (xml_node_ptr) malloc(sizeof(struct xml_node_t));
    if (!node) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: unable to allocate node.\n");
        return NULL;
    }
    node->name = strdup(type);
    contents_init(&node->attributes, 0);
    contents_init(&node->children, 0);
    node->content_size = 0;
    node->content = NULL;
    node->parent = NULL;
    return node;
}

static inline void xml_node_destruct(xml_node_ptr node)
{
    free(node->name);
    free(node->content);
    contents_end(&node->attributes);
    contents_end(&node->children);
    free(node);
}

static inline void xml_node_empty(xml_node_ptr node)
{
    size_t i;
    for (i = 0; i < node->attributes.num; ++i)
        free(node->attributes.data[i]);
    for (i = 0; i < node->children.num; ++i)
        xml_node_free((xml_node_ptr) node->children.data[i]);
}

void xml_node_free(xml_node_ptr node)
{
    if (NULL == node) return;
    xml_node_empty(node);
    xml_node_destruct(node);
}

static void xml_node_attr_load(xml_node_ptr node, const char *attrval)
{
    if (strchr(attrval, '='))
        contents_add(&node->attributes, strdup(attrval));
}

void xml_node_attr_add(xml_node_ptr node, const xml_char *name,
                       const xml_char *value)
{
    int ret;
    char *attr = NULL;
    ret = asprintf(&attr, " %s=\"%s\"", name, value);
    if (0 > ret) {
        fprintf(stderr, "WARN: unable to add attribute named \"%s\"\n", name);
        return;
    }
    contents_add(&node->attributes, attr);
}

void xml_node_attr_cpy_add(xml_node_ptr node, const xml_char *name,
                           const char *value)
{
    xml_node_attr_add(node, name, value);
}

char *xml_node_attr_get(xml_node_ptr node, const char *attrname)
{
    size_t attrsize = strlen(attrname);
    if (0 == attrsize) return NULL;
    for (size_t i = 0; i < node->attributes.num; ++i) {
        char *val = (char *) node->attributes.data[i], *end;
        if (!strncmp(attrname, val, attrsize)) {
            val = strchr(val, '=') + 2; /* Assume attr is like "attr="value"" */
            val = strdup(val); end = strrchr(val, '"'); *end = '\0';
            return val;
        }
    }
    return NULL;
}

void xml_node_child_add(xml_node_ptr node, xml_node_ptr child)
{
    contents_add(&node->children, child);
    child->parent = node;
}

xml_node_ptr xml_node_child_new(xml_node_ptr parent, xml_ns_ptr ns,
                                const xml_char *type, const xml_char *content)
{
    xml_node_ptr child = xml_node_new(ns, type);
    if (child) {
        if (content) {
            child->content = strdup(content);
            child->content_size = strlen(content);
        }
        xml_node_child_add(parent, child);
    }
    return child;
}

static void xml_node_content_add(xml_node_ptr node, const char *content)
{
    /* Concatenate all contents */
    size_t content_size = strlen(content) + 1;
    size_t new_size = node->content_size + content_size;
    char *new = (char *) realloc(node->content, new_size);
    memcpy(new + node->content_size, content, content_size);
    node->content = new; node->content_size = new_size;
}

void xml_node_merge(xml_node_ptr dest, xml_node_ptr src)
{
    contents_merge(&dest->attributes, &src->attributes);
    if (dest->content && src->content) {
        dest->content = strcat(dest->content, src->content);
        dest->content_size = strlen(dest->content);
    } else if (!dest->content)
        contents_merge(&dest->children, &src->children);
    xml_node_destruct(src);
}

int xml_node_has_child(xml_node_ptr node)
{
    return 0 != node->children.num;
}

/* Doc */
xml_doc_ptr xml_doc_new(const xml_char *version)
{
    xml_doc_ptr ret = (xml_doc_ptr)malloc(sizeof(struct xml_doc_t));
    ret->xml_version = strdup(version);
    ret->doctype = NULL;
    return ret;
}

void xml_doc_free(xml_doc_ptr doc)
{
    xml_node_free(doc->root);
    free(doc->xml_version);
    free(doc->doctype);
    free(doc);
}

xml_node_ptr xml_doc_set_root_element(xml_doc_ptr doc, xml_node_ptr node)
{
    xml_node_ptr old = doc->root;
    doc->root = node;
    return old;
}

void xml_dtd_subset_create(xml_doc_ptr doc, const xml_char *name,
                           const xml_char *externalid __netloc_attribute_unused,
                           const xml_char *systemid)
{
    int ret;
    if (doc->doctype) {
        fprintf(stderr, "WARN: Overwriting previous DTD: \"%s\"\n",
                doc->doctype);
        free(doc->doctype);
    }
    ret = asprintf(&doc->doctype, "<!DOCTYPE %s SYSTEM \"%s\">\n",
                       name, systemid);
    if (0 > ret)
        doc->doctype = NULL;
}

/* Char */
void xml_char_free(xml_char *s) {
    free(s);
}

xml_char *xml_char_strdup(const char *c) {
    return strdup(c);
}

/******************************************************************************/
/* Export */
/******************************************************************************/

static int xml_node_write(FILE *out, xml_node_ptr node, unsigned int depth)
{
    int ret = 0;
    size_t i;
    ret += fprintf(out, "%*s<%s", depth * 2, "", node->name);
    for (i = 0; i < node->attributes.num; ++i)
        ret += fprintf(out, "%s", (char *)node->attributes.data[i]);
    if (0 == node->children.num && !node->content)
        ret += fprintf(out, "/>\n");
    else if (node->content) {
        ret += fprintf(out, ">%s</%s>\n", node->content, node->name);
    } else { /* Cannot have both content and children: because. */
        ret += fprintf(out, ">\n");
        for (i = 0; i < node->children.num; ++i)
            ret += xml_node_write(out, node->children.data[i], depth + 1);
        ret += fprintf(out, "%*s</%s>\n", depth * 2, "", node->name);
    }
    return ret;
}

int xml_doc_write(const char *outpath, xml_doc_ptr doc, const char *enc,
                  int format __netloc_attribute_unused)
{
    FILE *out = fopen(outpath, "w");
    if (!out)
        return (fclose(out), -1);
    int ret = fprintf(out, "<?xml version=\"%s\" encoding=\"%s\"?>\n%s",
                      doc->xml_version, enc, doc->doctype ? doc->doctype : "");
    ret += xml_node_write(out, doc->root, 0);
    /* Close file */
    fclose(out);
    return ret;
}

/******************************************************************************/
/* Import */
/******************************************************************************/

static inline char *ignore_spaces(const char *buffer)
{
    return (char *)buffer + strspn(buffer, " \t\n");
}

static inline char *next_attr(const char *buffer)
{
    char *next = ignore_spaces(buffer);
    if (0 < strspn(next, "0123456789-."))
        /* Attribute must start with letter or _ */
        return NULL;
    else if (0 < strspn(next, "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789-."))
        return next;
    else
        return NULL;
}

xml_node_ptr xml_doc_get_root_element(const xml_doc_ptr doc)
{
    return doc->root;
}

char *xml_node_get_name(const xml_node_ptr node)
{
    return node->name;
}

size_t xml_node_get_num_children(const xml_node_ptr node)
{
    return node->children.num;
}

int xml_node_has_child_data(const xml_node_ptr node)
{
    return (0 != node->children.data);
}


xml_node_ptr xml_node_get_child(const xml_node_ptr node, int idx)
{
    if (idx < node->children.num) {
        return node->children.data[idx];
    } else {
        return NULL;
    }
}

xml_char *xml_node_get_content(const xml_node_ptr node)
{
    return node->content;
}


xml_doc_ptr xml_node_read_file(const char *path)
{
    size_t n = 0;
    ssize_t read;
    char *line = NULL, *buff = NULL, *xml_vers = NULL;
    xml_node_ptr crt_node = NULL;
    int parse_attr = 0;
    xml_doc_ptr doc = NULL;

    FILE *in = fopen(path, "r");
    if (!in) return NULL;
    size_t cpt = 0;
    while (-1 != (read = getline(&line, &n, in))) {
        cpt += 1;
        for (buff = ignore_spaces(line); buff < line + read;
             buff = ignore_spaces(buff)) {

            if (!parse_attr) {
                /* Remove xml header tag */
                if (!strncmp("<?xml ", buff, 6)) {
                    /* Retrieve XML version and encoding */
                    if (!doc && (xml_vers = strstr(buff, "version=\""))) {
                        char end = xml_vers[12]; xml_vers[12] = '\0';
                        doc = xml_doc_new(xml_vers + 9);
                        xml_vers[12] = end;
                    }
                    while (!(buff = strstr(buff, "?>"))) {
                        /* Potentially get next lines until the end of
                           the tag is found */
                        free(line); line = NULL;
                        read = getline(&line, &n, in);
                        if (-1 == read)
                            /* There should have been some tags before EOF */
                            goto ERROR;
                        buff = ignore_spaces(line);
                        if (!doc && (xml_vers = strstr(buff, "version=\""))) {
                            char end = xml_vers[12]; xml_vers[12] = '\0';
                            doc = xml_doc_new(xml_vers + 9);
                            xml_vers[12] = end;
                        }
                    }
                    buff += 2;
                }

                /* Doctype */
                else if ('<' == *buff && !strncmp("<!DOCTYPE", buff, 9)) {
                    if (!doc) goto ERROR; /* Wrong XML structure */
                    else if (doc->doctype) free(doc->doctype);
                    char *end = strchr(buff, '>');
                    doc->doctype = strndup(buff, end - buff + 1);
                    buff = end + 1;
                }

                /* New tag */
                else if ('<' == *buff && '/' != buff[1]) {
                    buff = next_attr(buff + 1);
                    if (!buff)
                        /* There should not be '<' alone */
                        goto ERROR;

                    /* There should not be any space tags' name */
                    xml_node_ptr new = NULL;
                    char *end = NULL, *eend = NULL;
                    end = strchr(buff, ' '); eend = strchr(buff, '>');
                    if ((end && eend && end < eend) || (end && !eend)) {
                        /* Multiple arguments */
                        *end = '\0';
                        new = xml_node_new(NULL, buff);
                        *end = ' '; buff = end + 1;
                    } else if ((end && eend && end > eend) || (!end && eend)) {
                        /* No attribute */
                        if ('/' == *(eend - 1))
                            eend -= 1;
                        *eend = '\0';
                        new = xml_node_new(NULL, buff);
                        *eend = *(eend + 1) == '>' ? '/' : '>';
                        buff = eend;
                    } else  {
                        /* Da Fuck iz dat kaïz ? */
                        assert(0);
                    }
                    parse_attr = 1;
                    if (!new) goto ERROR; /* Memory exhaustion (probably) */
                    else if (!doc) goto ERROR; /* Wrong XML structure */
                    else if (!crt_node) {
                        crt_node = new;
                        xml_doc_set_root_element(doc, new);
                    } else {
                        xml_node_child_add(crt_node, new);
                        crt_node = new;
                    }
                }

                /* Closing tag */
                else if ('<' == *buff) {
                    buff = next_attr(buff + 2);
                    if (strncmp(buff, crt_node->name, strlen(crt_node->name)))
                        /* Apparently wrong closing tag */
                        goto ERROR;
                    while (!(buff = strchr(buff, '>'))) {
                        /* Potentially get next lines until the end of
                           the tag is found */
                        free(line); line = NULL;
                        read = getline(&line, &n, in);
                        if (-1 == read)
                            /* There should have been some tags before EOF */
                            goto ERROR;
                        buff = ignore_spaces(line);
                    }
                    buff += 1;
                    crt_node = crt_node->parent;
                }

                /* Reading content */
                else {
                    char *end = NULL;
                    while (!(end = strchr(buff, '<'))) {
                        xml_node_content_add(crt_node, buff);
                        /* Potentially get next lines until the next
                           tag is found */
                        free(line); line = NULL;
                        read = getline(&line, &n, in);
                        if (-1 == read)
                            /* There should have been some tags before EOF */
                            goto ERROR;
                        buff = ignore_spaces(line);
                    }
                    *end = '\0';
                    xml_node_content_add(crt_node, buff);
                    *end = '<'; buff = end;
                }
            }

            else { /* Reading attributes */
                if ('/' == *buff && '>' == buff[1]) {
                    /* ending self closing tag */
                    parse_attr = 0;
                    crt_node = crt_node->parent;
                    buff += 2;
                } else if ('>' == *buff) {
                    /* end the current tag */
                    parse_attr = 0;
                    buff += 1;
                } else {
                    char *end = NULL, *eend = NULL;
                    /* There should not be any new line in attributes */
                    end  = strchr(buff, ' ');
                    /* Find the second quote position */
                    eend = strchr(strchrnul(buff, '"'), '"');
                    /* Find the first between attribute-separating space and
                       attribute-closing quote */
                    if (end && eend && end < eend) {
                        /* end points to a quoted space.
                           Find one that is not enclosed */
                        end = strchr(eend, ' ');
                    }
                    eend = strchr(buff, '>');
                    if ((end && eend && end < eend) || (end && !eend)) {
                        /* Multiple arguments */
                        *end = '\0';
                        xml_node_attr_load(crt_node, buff);
                        *end = ' '; buff = end + 1;
                    } else if ((end && eend && end > eend) || (!end && eend)) {
                        /* Last argument */
                        if ('/' == *(end = eend - 1)) {
                            /* Self closing ? */
                            *end = '\0';
                            xml_node_attr_load(crt_node, buff);
                            *end = '/'; buff = end;
                        } else {
                            *eend = '\0';
                            xml_node_attr_load(crt_node, buff);
                            *eend = '>'; buff = eend;
                        }
                    } else  {
                        /* Da Fuck iz dat kaïz ? */
                        assert(0);
                    }
                }
            }
        }
        free(line); line = NULL;
    }
    free(line);
    fclose(in);
    return doc;
    
 ERROR:
    free(line);
    fclose(in);
    xml_doc_free(doc);
    return NULL;
}

xml_doc_ptr xml_reader_init(const char *path)
{
    return xml_node_read_file(path);
}

int xml_reader_clean_and_out(xml_doc_ptr doc)
{
    xml_doc_free(doc);
    return NETLOC_SUCCESS;
}

/******************************************************************************/

#endif
