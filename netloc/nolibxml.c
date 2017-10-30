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

#include <private/netloc.h>
#include <private/autogen/config.h>
#include <private/netloc.h>
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
    ++contents->num;
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

static char *xml_node_attr_get(xml_node_ptr node, const char *attrname)
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

static inline char *ignore_spaces(char *buffer)
{
  return buffer + strspn(buffer, " \t\n");
}

static inline char *next_attr(char *buffer)
{
    char *next = ignore_spaces(buffer);
    if (0 < strspn(buffer, "abcdefghijklmnopqrstuvwxyz_"))
        return next;
    else
        return NULL;
}

static xml_doc_ptr xml_node_read_file(const char *path)
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
        ++cpt;
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
                            --eend;
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
                    /* There should not be any space in attributes */
                    end = strchr(buff, ' '); eend = strchr(buff, '>');
                    if ((end && eend && end < eend) || (end && !eend)) {
                        /* Multiple arguments */
                        *end = '\0';
                        xml_node_attr_load(crt_node, buff);
                        *end = ' '; buff = end + 1;
                    } else if ((end && eend && end > eend) || (!end && eend)) {
                        /* Last argument */
                        *eend = '\0';
                        xml_node_attr_load(crt_node, buff);
                        *eend = '>'; buff = eend + 1;
                        parse_attr = 0;
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

/******************************************************************************/

/**
 * Load the netloc partition as described in the xml file, of which
 * \ref part_node is a valid pointer to a DOM element.
 *
 * The returned element is to be added to the \ref
 * netloc_topology_t. If NULL is returned, then the partition is to be
 * ignored (i.e., it may be invalid or the /extra+structural/
 * partition).
 *
 * \param part_node A valid XML DOM node pointing to the proper <partition> tag
 * \param hwlocpath The path to the directory containing the hwloc
 *                  topology files
 * \param hwloc_topos A valid pointer to the hwloc_topos field in
 *                    \ref netloc_topology_t
 * \param topology A valid pointer to the current topology being loaded
 *
 * Returns
 *   A newly allocated and initialized pointer to the partition information.
 */
static netloc_partition_t *
netloc_part_xml_load(xml_node_ptr part_node, char *hwlocpath,
                     netloc_hwloc_topology_t **hwloc_topos,
                     netloc_topology_t *topology);

/**
 * Load the netloc node as described in the xml file, of which
 * \ref it_node is a valid pointer to a DOM element.
 *
 * The returned element is to be added to the \ref
 * netloc_topology_t. If the \ref netloc_node_t returned has nsubnodes
 * > 0, this means that the node is virtual. The subnodes (contained
 * in the node->subnodes array) have to be added before the virtual
 * node to ease the hashtable liberation.
 *
 * \param it_node A valid XML DOM node pointing to the proper <node> tag
 * \param hwlocpath The path to the directory containing the hwloc topology
 *                  files
 * \param hwloc_topos A valid pointer to the hwloc_topos field in
 *                    \ref netloc_topology_t
 *
 * Returns
 *   A newly allocated and initialized pointer to the node information.
 */
static netloc_node_t *
netloc_node_xml_load(xml_node_ptr it_node, char *hwlocpath,
                     netloc_hwloc_topology_t **hwloc_topos);

/**
 * Load the netloc edge as described in the xml file, of which
 * \ref it_edge is a valid pointer to a DOM element.
 *
 * The returned element is to be added to the corresponding \ref
 * netloc_node_t. The node has to be already part of the \ref
 * netloc_topology_t
 *
 * \param it_edge A valid XML DOM node pointing to the proper <connexion> tag
 * \param topology A valid pointer to the current topology being loaded
 * \param partition A valid pointer to the current partition being loaded
 *
 * Returns
 *   A newly allocated and initialized pointer to the edge information.
 */
static netloc_edge_t *
netloc_edge_xml_load(xml_node_ptr it_edge, netloc_topology_t *topology,
                     netloc_partition_t *partition);

/**
 * Load the netloc physical link as described in the xml file, of which
 * \ref it_link is a valid pointer to a DOM element.
 *
 * The returned element is to be added to the \ref netloc_edge_t.
 *
 * \param it_link A valid XML DOM node pointing to the proper <link> tag
 * \param edge A valid pointer to the current edge being loaded
 * \param partition A valid pointer to the current partition being loaded
 *
 * Returns
 *   A newly allocated and initialized pointer to the physical link information.
 */
static netloc_physical_link_t *
netloc_physical_link_xml_load(xml_node_ptr it_link, netloc_edge_t *edge,
                              netloc_partition_t *partition);

int netloc_topology_nolibxml_load(const char *path,
                                  netloc_topology_t **ptopology)
{
    int ret = NETLOC_ERROR;
    char *buff;
    xml_node_ptr machine_node, net_node = NULL, crt_node = NULL;
    xml_doc_ptr doc = NULL;
    netloc_topology_t *topology = NULL;
    netloc_hwloc_topology_t *hwloc_topos = NULL;
    char *hwlocpath = NULL;

    if (NULL == ptopology) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: invalid pointer given as parameter\n");
        return NETLOC_ERROR;
    }
    if (NULL == path || 0 >= strlen(path)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: invalid path given (%s)\n", path);
        return NETLOC_ERROR_NOENT;
    }

    topology = netloc_topology_construct();
    if (NULL == topology)
        return NETLOC_ERROR;

    doc = xml_node_read_file(path);
    machine_node = doc->root;
    if (NULL == machine_node) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: unable to parse the XML file.\n");
        return (netloc_topology_destruct(topology), NETLOC_ERROR_NOENT);
    }
    if ( !strcmp("machine", machine_node->name)
         && 0 < machine_node->children.num ) {
        /* Check netloc file version */
        buff = xml_node_attr_get(machine_node, "version");
        if (!buff ||
            0 != strcmp(NETLOC_STR_VERS(NETLOCFILE_VERSION_2_0), buff)) {
            if (netloc__xml_verbose())
                fprintf(stderr, "ERROR: incorrect version number (\"%s\"), "
                        "please generate your input file again.\n", buff);
            free(buff); buff = NULL;
            netloc_topology_destruct(topology); topology = NULL;
            goto clean_and_out;
        }
        free(buff); buff = NULL;
        /* Retrieve hwloc path */
        size_t net_id = 1;
        if (net_id < machine_node->children.num &&
            (crt_node = (xml_node_ptr) machine_node->children.data[0])
            && !strcmp("hwloc_path", crt_node->name) && crt_node->content) {
            hwlocpath = strdup(crt_node->content);
        } else {
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: unable to read hwloc path in %s\n",
                        path);
            --net_id;
        }
        if (net_id < machine_node->children.num) {
            /* Find machine topology root_node */
            net_node = (xml_node_ptr) machine_node->children.data[net_id];
        }
    }
    if (!net_node) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: invalid XML file. Please, generate your "
                    "input file again.\n");
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }
    if (hwlocpath) {
        DIR *hwlocdir;
        char *realhwlocpath;
        if (hwlocpath[0] != '/') {
            char *path_tmp = strdup(path);
            asprintf(&realhwlocpath, "%s/%s", dirname(path_tmp), hwlocpath);
            free(path_tmp);
            free(hwlocpath);
            hwlocpath = realhwlocpath;
        }
        if (!(hwlocdir = opendir(hwlocpath))) {
            if (netloc__xml_verbose())
                fprintf(stderr, "ERROR: could not open hwloc directory: "
                        "\"%s\"\n", hwlocpath);
            perror("opendir");
            netloc_topology_destruct(topology);
            topology = NULL;
            goto clean_and_out;
        } else {
            closedir(hwlocdir);
        }
    }

    if (NULL == net_node || 0 != strcmp("network", net_node->name)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read the topology in %s.\n", path);
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }
    netloc_network_type_t transport_type;
    /* Check transport type */
    buff = xml_node_attr_get(net_node, "transport");
    if (!buff) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: transport type not found, please generate "
                    "your input file again.\n");
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    } else if (NETLOC_NETWORK_TYPE_INVALID ==
               (transport_type = netloc_network_type_decode(buff))) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: invalid network type (\"%s\"), please "
                    "generate your input file again.\n", buff);
        free(buff); buff = NULL;
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }
    free(buff); buff = NULL;
    /* Retrieve subnet */
    char *subnet = NULL;
    if (0 < net_node->children.num
        && (crt_node = (xml_node_ptr) net_node->children.data[0])
        && !strcmp("subnet", crt_node->name) && crt_node->content) {
        subnet = strdup(crt_node->content);
    } else {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read the subnet in %s\n", path);
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }

    /* Read partitions from file */
    for (size_t part_id = 1; part_id < net_node->children.num; ++part_id) {
        xml_node_ptr part = net_node->children.data[part_id];
        if (!part) continue;
        /* Load partition */
        netloc_partition_t *partition = NULL;
        partition =
            netloc_part_xml_load(part, hwlocpath, &hwloc_topos, topology);
        if (partition)
            HASH_ADD_STR(topology->partitions, name, partition);
    }

    /* Set topology->physical_links->other_way */
    netloc_physical_link_t *plink = NULL,
        *plink_tmp = NULL, *plink_found = NULL;
    HASH_ITER(hh, topology->physical_links, plink, plink_tmp) {
        HASH_FIND(hh, topology->physical_links, &plink->other_way_id,
                  sizeof(unsigned long long int), plink_found);
        if (NULL == plink_found) {
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: strangely enough, the corresponding "
                        "reverse physical link seems to be absent...\n");
        } else {
            plink->other_way = plink_found;
            if (NULL == plink->edge->other_way)
                plink->edge->other_way = plink_found->edge;
        }
    }

    /* Change from hashtable to array for hwloc topologies */
    topology->nb_hwloc_topos = HASH_COUNT(hwloc_topos);
    if (0 < topology->nb_hwloc_topos) {
        topology->hwlocpaths = malloc(sizeof(char *[topology->nb_hwloc_topos]));
        netloc_hwloc_topology_t *ptr, *ptr_tmp;
        HASH_ITER(hh, hwloc_topos, ptr, ptr_tmp) {
            topology->hwlocpaths[ptr->hwloc_topo_idx] = ptr->path;
            HASH_DEL(hwloc_topos, ptr);
            free(ptr);
        }
    } else {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: no hwloc topology found\n");
    }

    topology->topopath       = strdup(path);
    topology->hwloc_dir_path = strdup(hwlocpath);
    topology->subnet_id      = strdup(subnet);
    topology->transport_type = transport_type;

    if (netloc_topology_find_reverse_edges(topology) != NETLOC_SUCCESS) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot find reverse corresponding "
                    "edges.\n");
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }
    ret = NETLOC_SUCCESS;

 clean_and_out:
    free(subnet);
    free(hwlocpath);
    xml_doc_free(doc);
    *ptopology = topology;

    return ret;
}

static netloc_partition_t * /* to become explicit */
netloc_part_xml_load(xml_node_ptr part, char *hwloc_path,
                     netloc_hwloc_topology_t **hwloc_topos,
                     netloc_topology_t *topology)
{
    xml_node_ptr explicit_node = NULL, nodes_node, edges_node;
    char *strBuff, *buff;
    
    /* Check partition's name */
    netloc_partition_t *partition;
    buff = xml_node_attr_get(part, "name");
    if (!buff || !strlen(buff)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: cannot read partition's name.\n");
        if (!buff)
            buff = "";
    }
    if ('/' == *buff) { /* Exclude /extra+structural/ partition */
        partition = NULL;
    } else {
        unsigned int part_id = HASH_COUNT(topology->partitions);
        partition = netloc_partition_construct(part_id, buff);
    }
    if ('\0' != *buff)
        free(buff);
    buff = NULL;

    /* Check for <explicit> tag */
    if (!part->children.num
        || !(explicit_node = (xml_node_ptr) part->children.data[0])
        || 0 != strcmp("explicit", explicit_node->name)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: no \"explicit\" tag.\n");
        return partition;
    }

    /* Check partition's size */
    long int nnodes = 0;
    buff = xml_node_attr_get(explicit_node, "size");
    if (!buff || (!(nnodes = strtol(buff, &strBuff, 10))
                  && strBuff == buff)){
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: cannot read partition's size.\n");
    }
    free(buff); buff = NULL; strBuff = NULL;

    if (!explicit_node->children.num) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: empty \"explicit\" tag.\n");
        return partition;
    }

    /* Read nodes from file */

    /* Check for <nodes> tag */
    if (!explicit_node->children.num
        || !(nodes_node = (xml_node_ptr) explicit_node->children.data[0])
        || 0 != strcmp("nodes", nodes_node->name)
        || (!nodes_node->children.num && 0 < nnodes)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: no \"nodes\" tag, but %ld nodes "
                    "required.\n", nnodes);
        return partition;
    }

    for (size_t node_id = 0; node_id < nodes_node->children.num; ++node_id) {
        xml_node_ptr it_node = (xml_node_ptr) nodes_node->children.data[node_id];
        if (!it_node) continue;
        netloc_node_t *node = NULL;
        /* Prefetch physical_id to know if it's worth loading the node */
        free(buff); buff = NULL;
        buff = xml_node_attr_get(it_node, "mac_addr");
        if (!buff) continue;
        HASH_FIND_STR(topology->nodes, buff, node);
        if (!node) {
            node = netloc_node_xml_load(it_node, hwloc_path, hwloc_topos);
            if (!node) {
                if (netloc__xml_verbose())
                    fprintf(stderr, "WARN: node cannot be loaded. Skipped\n");
                continue;
            }
            /* Add to the hashtables */
            HASH_ADD_STR(topology->nodes, physical_id, node);
            for (unsigned int n = 0; n < node->nsubnodes; ++n) {
                HASH_ADD_STR(topology->nodes, physical_id,
                             node->subnodes[n]);
            }
            if (NETLOC_NODE_TYPE_HOST == node->type
                && 0 < strlen(node->hostname)) {
                HASH_ADD_KEYPTR(hh2, topology->nodesByHostname, node->hostname,
                                strlen(node->hostname), node);
            }
        }
        /* Add to the partition */
        if (partition) {
            for (unsigned int n = 0; n < node->nsubnodes; ++n) {
                utarray_push_back(node->subnodes[n]->partitions,
                                  &partition);
            }
            utarray_push_back(partition->nodes, &node);
            utarray_push_back(node->partitions, &partition);
        }
    }
    free(buff); buff = NULL;
    if (partition && utarray_len(partition->nodes) != nnodes) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: found %u nodes, but %ld required.\n",
                    utarray_len(partition->nodes), nnodes);
    }

    /* Read edges from file */

    /* Check for <connexions> tag:
       - explicit_node has to have children
       - if nnodes > 0, then, there has already been 1 child, so we need
       at least 2
       - we set edges_node to the last children, and it can't be NULL
       - edges_node's name has to be connexions
    */
    size_t nchildren = explicit_node->children.num;
    if (!explicit_node->children.num || (nnodes > 0 && 2 > nchildren)
        || !(edges_node =
             (xml_node_ptr) explicit_node->children.data[nchildren - 1])
        || strcmp("connexions", edges_node->name)) {
        if ( 1 < nnodes)
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: no \"connexions\" tag.\n");
        return partition;
    } else if (!edges_node->children.num || !edges_node->children.data) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: empty \"connexions\" tag.\n");
        return partition;
    }
    for (size_t edge_id = 0; edge_id < edges_node->children.num; ++edge_id) {
        xml_node_ptr it_edge =
            (xml_node_ptr) edges_node->children.data[edge_id];
        netloc_edge_t *edge =
            netloc_edge_xml_load(it_edge, topology, partition);
        if (partition && edge) {
            utarray_push_back(partition->edges, &edge);
        }
    }
    return partition;
}

static netloc_node_t *
netloc_node_xml_load(xml_node_ptr it_node, char *hwlocpath,
                     netloc_hwloc_topology_t **hwloc_topos) {
    xml_node_ptr tmp = NULL;
    char *strBuff = NULL, *buff = NULL;
    size_t strBuffSize, buffSize;
    netloc_node_t *node = netloc_node_construct();
    /* read hostname */
    strBuff = xml_node_attr_get(it_node, "name");
    if (!strBuff || 0 >= strlen(strBuff)) {
        free(strBuff); strBuff = strdup("");
    }
    /* set physical_id */
    buff = xml_node_attr_get(it_node, "mac_addr");
    if (buff && 0 < strlen(buff)) {
        strncpy(node->physical_id, buff, 20);
        /* Should be shorter than 20 */
        node->physical_id[19] = '\0'; /* If a problem occurs */
        free(buff); buff = NULL;
    } else {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: node \"%s\" has no physical address and "
                    "is not added to the topology.\n",
                    strBuff && strlen(strBuff) ? strBuff : "(no name)");
        free(buff); free(strBuff);
        netloc_node_destruct(node);
        return NULL;
    }
    /* set hostname */
    node->hostname = strBuff; strBuff = NULL;
    /* set type (i.e., host or switch) */
    buff = xml_node_attr_get(it_node, "type");
    if (buff)
        node->type = netloc_node_type_decode(buff);
    free(buff); buff = NULL;
    /* Set description */
    if (it_node->children.num && it_node->children.data
        && (tmp = it_node->children.data[0])
        && 0 == strcmp("description", tmp->name) && tmp->content) {
        node->description = strdup(tmp->content);
    }
    /* set hwloc topology field iif node is a host */
    if (NETLOC_NODE_TYPE_HOST == node->type
        && (buff = xml_node_attr_get(it_node, "hwloc_file"))
        && 0 < (buffSize = strlen(buff))) {
        netloc_hwloc_topology_t *hwloc_topo = NULL;
        char *refname;
        strBuffSize = asprintf(&strBuff, "%s/%s", hwlocpath, buff);
        if (5 > strBuffSize) { /* bad return from asprintf() */
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: invalid topology file \"%s/%s\", or "
                        "memory exhaustion\n", hwlocpath, buff);
        } else if (9 < strBuffSize
                   && 0 == strcmp(".diff.xml", &strBuff[strBuffSize-9])) {
            /* hwloc_file point to a diff file */
            hwloc_topology_diff_t diff;
            if (0 <= hwloc_topology_diff_load_xml(strBuff, &diff, &refname)
                && refname) {
                /* Load diff file to check on refname */
                hwloc_topology_diff_destroy(diff);
                free(strBuff);
                strBuffSize = asprintf(&strBuff, "%s/%s", hwlocpath, refname);
                free(refname);
            } else {
                if (netloc__xml_verbose())
                    fprintf(stderr, "WARN: no refname for topology file "
                            "\"%s/%s\"\n", hwlocpath, buff);
            }
        }
        HASH_FIND(hh, *hwloc_topos, strBuff, (unsigned)strBuffSize, hwloc_topo);
        if (!hwloc_topo) {
            /* The topology cannot be retrieved in the hashtable */
            size_t hwloc_topo_idx = (size_t)HASH_COUNT(*hwloc_topos);
            hwloc_topo = malloc(sizeof(netloc_hwloc_topology_t));
            hwloc_topo->path = strdup(strBuff);
            hwloc_topo->hwloc_topo_idx = hwloc_topo_idx;
            node->hwloc_topo_idx = hwloc_topo_idx;
            ++hwloc_topo_idx;
            HASH_ADD_STR(*hwloc_topos, path, hwloc_topo);
        } else {
            node->hwloc_topo_idx = hwloc_topo->hwloc_topo_idx;
        }
        free(strBuff); strBuff = NULL;
        free(buff); buff = NULL;
    } else if (NETLOC_NODE_TYPE_SWITCH == node->type
               && (buff = xml_node_attr_get(it_node, "virtual"))
               && 0 < (buffSize = strlen(buff))
               && 0 == strncmp("yes", buff, 3)) {
        /* Virtual node */
        free(buff); buff = NULL;
        buff = xml_node_attr_get(it_node, "size");
        if (1 != sscanf(buff, "%u", &node->nsubnodes)) {
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: cannot read how many subnodes are "
                        "included into the virtual node \"%s\"\n",
                        node->physical_id);
        }
        free(buff); buff = NULL;
        /* Add subnodes */
        if (!node->description) {
            tmp = (xml_node_ptr) it_node->children.data[0];
            node->description = strndup(node->physical_id, 20);
        } else {
            tmp = (xml_node_ptr) it_node->children.data[1];
        }
        if (!tmp || !tmp->name || 0 != strcmp("subnodes", tmp->name)) {
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: virtual node \"%s\" is empty, and thus, "
                        "ignored\n", node->physical_id);
            netloc_node_destruct(node);
            return NULL;
        }
        /* Allocate subnodes array */
        node->subnodes = malloc(sizeof(netloc_node_t *[node->nsubnodes]));
        if (!node->subnodes) {
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: unable to allocate the memory for "
                        "virtual node \"%s\" subnodes. This node is thus "
                        "ignored\n", node->physical_id);
            netloc_node_destruct(node);
            return NULL;
        }
        for (size_t subnode_id = 0;
             subnode_id < tmp->children.num; ++subnode_id) {
            xml_node_ptr it_subnode = tmp->children.data[subnode_id];
            netloc_node_t *subnode =
                netloc_node_xml_load(it_subnode, hwlocpath, hwloc_topos);
            if (subnode)
                subnode->virtual_node = node;
            node->subnodes[subnode_id] = subnode;
        }
        /* Check we found all the subnodes */
        if (tmp->children.num != node->nsubnodes) {
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: expecting %u subnodes, but %zu found\n",
                        node->nsubnodes, tmp->children.num);
        }
    }
    return node;
}

static netloc_edge_t *
netloc_edge_xml_load(xml_node_ptr it_edge, netloc_topology_t *topology,
                     netloc_partition_t *partition)
{
    xml_node_ptr tmp;
    char *buff = NULL, *strBuff = NULL;
    size_t strBuffSize;
    netloc_edge_t *edge = netloc_edge_construct();
    /* set total_gbits */
    float total_gbits;
    buff = xml_node_attr_get(it_edge, "bandwidth");
    if (buff && 0 < strlen(buff)) {
        total_gbits = strtof(buff, &strBuff);
        if (0 == total_gbits && strBuff == buff)
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: cannot read connexion's bandwidth.\n");
        free(buff); buff = NULL; strBuff = NULL;
        edge->total_gbits = total_gbits;
    }
    /* get number of links */
    unsigned int nlinks;
    buff = xml_node_attr_get(it_edge, "nblinks");
    if (!buff || (1 > sscanf(buff, "%u", &nlinks))) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: cannot read connexion's physical links.\n");
    } else if (0 >= nlinks) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: less than 1 connexion's physical link "
                    "required (%u).\n", nlinks);
    }
    free(buff); buff = NULL;
    /* Move tmp to the proper xml node and set src node */
    if (0 < it_edge->children.num && it_edge->children.data
        && (tmp = it_edge->children.data[0]) && 0 == strcmp("src", tmp->name)
        && tmp->content) {
        netloc_topology_find_node(topology, tmp->content, edge->node);
    } else {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot find connexion's source node.\n");
        goto ERROR;
    }
    /* Move tmp to the proper xml node and set dest node */
    if (1 < it_edge->children.num && it_edge->children.data
        && (tmp = it_edge->children.data[1]) && 0 == strcmp("dest", tmp->name)
        && tmp->content) {
        netloc_topology_find_node(topology, tmp->content, edge->dest);
    } else {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot find connexion's destination "
                    "node.\n");
        goto ERROR;
    }
    /* Add edge to its node if it does not already exists */
    netloc_edge_t *edge_tmp = NULL;
    HASH_FIND_PTR(edge->node->edges, &edge->dest, edge_tmp);
    if (NULL == edge_tmp) {
        HASH_ADD_PTR(edge->node->edges, dest, edge);
        /* Set partition */
        if (partition)
            utarray_push_back(edge->partitions, &partition);
    } else {
        /* Set partition */
        if (partition) {
            utarray_push_back(edge_tmp->partitions, &partition);
            for (unsigned int se = 0; se < edge_tmp->nsubedges; ++se)
                utarray_push_back(edge_tmp->subnode_edges[se]->partitions,
                                  &partition);
        }
        /* Edge already created from another partition */
        netloc_edge_destruct(edge);
        return edge_tmp;
    }

    if ((buff = xml_node_attr_get(it_edge, "virtual"))
        && 0 < (strBuffSize = strlen(buff))
        && 0 == strncmp("yes", buff, 3)) {
        /*** VIRTUAL EDGE ***/
        free(buff); buff = NULL;
        /* Move tmp to the proper xml node */
        unsigned int nsubedges;
        if (!(2 < it_edge->children.num && it_edge->children.data
              && (tmp = it_edge->children.data[2])
              && 0 == strcmp("subconnexions", tmp->name)
              && tmp->children.num)) {
            if (netloc__xml_verbose())
                fprintf(stderr, "ERROR: cannot find the subedges. Failing to "
                        "read this connexion\n");
            goto ERROR;
        }
        buff = xml_node_attr_get(tmp, "size");
        if (!buff || (1 > sscanf(buff, "%u", &nsubedges))) {
            if (netloc__xml_verbose())
                fprintf(stderr, "ERROR: cannot read virtual edge subnodes.\n");
            goto ERROR;
        } else if (2 > nsubedges) {
            if (netloc__xml_verbose())
                fprintf(stderr, "WARN: less than 2 edges (%u).\n", nsubedges);
        }
        edge->nsubedges = nsubedges;
        edge->subnode_edges =
            (netloc_edge_t **)malloc(sizeof(netloc_edge_t *[nsubedges]));
        free(buff); buff = NULL;
        netloc_edge_t *subedge = NULL;
        for (size_t se = 0; se < tmp->children.num; ++se) {
            subedge = netloc_edge_xml_load(tmp->children.data[se],
                                           topology, partition);
            edge->subnode_edges[se] = subedge;
            if (!subedge) {
                if (netloc__xml_verbose())
                    fprintf(stderr,
                            "WARN: cannot read subconnexion #%zu\n", se);
                continue;
            }
            total_gbits -= subedge->total_gbits;
            utarray_concat(edge->node->physical_links, subedge->physical_links);
            utarray_concat(edge->physical_links, subedge->physical_links);
        }
    } else {

        /* Read physical links from file */

        /* Check for <links> tag */
        if (!(2 < it_edge->children.num && it_edge->children.data
              && (tmp = it_edge->children.data[2])
              && 0 == strcmp("links", tmp->name)
              && tmp->children.num)) {
            if (netloc__xml_verbose())
                fprintf(stderr, "ERROR: no \"links\" tag.\n");
            goto ERROR;
        }
        netloc_physical_link_t *link = NULL;
        for (size_t l = 0; l < tmp->children.num; ++l) {
            link = netloc_physical_link_xml_load(tmp->children.data[l],
                                                 edge, partition);
            if (link) {
                total_gbits -= link->gbits;
                utarray_push_back(edge->node->physical_links, &link);
                utarray_push_back(edge->physical_links, &link);
                HASH_ADD(hh, topology->physical_links, id,
                         sizeof(unsigned long long int), link);
            }
        }
    }
#ifdef NETLOC_DEBUG
    /* Check proper value for edge->total_gbits */
    if (0 != total_gbits) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: erroneous value read from file for edge "
                    "total bandwidth. \"%f\" instead of %f (calculated).\n",
                    edge->total_gbits, edge->total_gbits - total_gbits);
    }
    /* Check proper value for nlinks and utarray_len(edge->physical_links) */
    if (nlinks != utarray_len(edge->physical_links)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "WARN: erroneous value read from file for edge "
                    "count of physical links. %u requested, but only %u "
                    "found\n", nlinks, utarray_len(edge->physical_links));
    }
#endif /* NETLOC_DEBUG */
    return edge;
 ERROR:
    netloc_edge_destruct(edge);
    return NULL;
}

static netloc_physical_link_t *
netloc_physical_link_xml_load(xml_node_ptr it_link, netloc_edge_t *edge,
                              netloc_partition_t *partition)
{
    char *buff = NULL, *strBuff = NULL;
    netloc_physical_link_t *link = netloc_physical_link_construct();
    /* set ports */
    int tmpport;
    buff = xml_node_attr_get(it_link, "srcport");
    if (!buff ||
        (!(tmpport = strtol(buff, &strBuff, 10)) && strBuff == buff)){
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read physical link's source "
                    "port.\n");
        goto ERROR;
    }
    free(buff); buff = NULL;
    link->ports[0] = tmpport;
    buff = xml_node_attr_get(it_link, "destport");
    if (!buff ||
        (!(tmpport = strtol(buff, &strBuff, 10)) && strBuff == buff)){
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read physical link's destination "
                    "port.\n");
        goto ERROR;
    }
    free(buff); buff = NULL;
    link->ports[1] = tmpport;
    /* set speed */
    buff = xml_node_attr_get(it_link, "speed");
    if (!buff || 0 >= strlen(buff)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read physical link's speed.\n");
        goto ERROR;
    }
    link->speed = buff; buff = NULL;
    /* set width */
    buff = xml_node_attr_get(it_link, "width");
    if (!buff || 0 >= strlen(buff)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read physical link's width.\n");
        goto ERROR;
    }
    link->width = buff; buff = NULL;
    /* set gbits */
    float gbits;
    buff = xml_node_attr_get(it_link, "bandwidth");
    if (!buff || 0 >= strlen(buff)
        || (!(gbits = strtof(buff, &strBuff)) && strBuff == buff)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read physical link's bandwidth.\n");
        goto ERROR;
    }
    free(buff); buff = NULL; strBuff = NULL;
    /* set id */
    unsigned long long int id_read;
    buff = xml_node_attr_get(it_link, "logical_id");
    if (!buff || 0 >= strlen(buff) || 1 > sscanf(buff, "%llu", &id_read)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read physical link's id.\n");
        goto ERROR;
    }
    link->id = id_read;
    free(buff); buff = NULL; strBuff = NULL;
    /* set other_way_id */
    buff = xml_node_attr_get(it_link, "reverse_logical_id");
    if (!buff || 0 >= strlen(buff) || 1 > sscanf(buff, "%llu", &id_read)) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: cannot read reverse physical link's id.\n");
        goto ERROR;
    }
    link->other_way_id = id_read;
    free(buff); buff = NULL; strBuff = NULL;
    /* set description */
    if (it_link->content) {
        link->description = strdup(it_link->content);
    }
    /* set src, dest, partition, edge */
    link->src   = edge->node;
    link->dest  = edge->dest;
    link->edge  = edge;
    link->gbits = gbits;
    if (partition)
        utarray_push_back(link->partitions, &partition);

    return link;

 ERROR:
    netloc_physical_link_destruct(link);
    free(buff); buff = NULL;
    return NULL;
}

#endif
