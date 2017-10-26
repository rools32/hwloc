/*
 * Copyright © 2016-2017 Inria.  All rights reserved.
 *
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 * See COPYING in top-level directory.
 *
 * $HEADER$
 */

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <libgen.h>

#include <private/netloc.h>
#include <private/netloc-xml.h>
#include "netloc.h"

#define JSON_DRAW_FILE_LINK_ID "id"
#define JSON_DRAW_FILE_LINK_SRC "from"
#define JSON_DRAW_FILE_LINK_SRC_PORT "src_port"
#define JSON_DRAW_FILE_LINK_DST "to"
#define JSON_DRAW_FILE_LINK_DST_PORT "dst_port"
#define JSON_DRAW_FILE_LINK_WIDTH "width"
#define JSON_DRAW_FILE_LINK_SPEED "speed"
#define JSON_DRAW_FILE_LINK_GBITS "gbits"
#define JSON_DRAW_FILE_LINK_OTHER_WAY "reverse"
#define JSON_DRAW_FILE_LINK_PARTITIONS "part"
#define JSON_DRAW_FILE_EDGE_ID "id"
#define JSON_DRAW_FILE_EDGE_SRC "from"
#define JSON_DRAW_FILE_EDGE_DST "to"
#define JSON_DRAW_FILE_EDGE_GBITS "gbits"
#define JSON_DRAW_FILE_EDGE_LINKS "links"
#define JSON_DRAW_FILE_EDGE_PARTITIONS "part"
#define JSON_DRAW_FILE_EDGE_SUBEDGES "subedges"
#define JSON_DRAW_FILE_EDGE_OTHER_WAY "reverse"
#define JSON_DRAW_FILE_NODE_ID "id"
#define JSON_DRAW_FILE_NODE_EDGES "edges"
#define JSON_DRAW_FILE_NODE_MERGED "merged"
#define JSON_DRAW_FILE_NODE_SUBNODES "sub"
#define JSON_DRAW_FILE_NODE_PARTITIONS "part"
#define JSON_DRAW_FILE_NODE_DESC "desc"
#define JSON_DRAW_FILE_NODE_HOSTNAME "hostname"
#define JSON_DRAW_FILE_NODE_HWLOCTOPO "topo"
#define JSON_DRAW_FILE_NODE_EDGES "edges"
#define JSON_DRAW_FILE_NODE_TYPE "type"
#define JSON_DRAW_FILE_EDGES_LIST "list"
#define JSON_DRAW_FILE_PATH_ID "id"
#define JSON_DRAW_FILE_PATH_LINKS "links"
#define JSON_DRAW_FILE_PATHS "paths"

#define JSON_DRAW_FILE_GRAPH_TYPE "type"
#define JSON_DRAW_FILE_NODES "nodes"
#define JSON_DRAW_FILE_EDGES "edges"
#define JSON_DRAW_FILE_LINKS "links"
#define JSON_DRAW_FILE_PARTITIONS "partitions"
#define JSON_DRAW_FILE_HWLOCTOPOS "hwloctopos"

/******************************************************************************/
/* Functions to handle JSON */
/******************************************************************************/
typedef enum {
    JSON_STRING,
    JSON_INT,
    JSON_UINT,
    JSON_ULLINT,
    JSON_FLOAT,
    JSON_ARRAY,
    JSON_DICT
} json_type;

typedef struct {
    int num;
    int allocated;
    char **strings;
} contents_t;

typedef struct {
    json_type type;
    contents_t *contents;
} json_t;

static contents_t *contents_new(int allocated)
{
    contents_t *contents = (contents_t *)malloc(sizeof(contents_t));
    if (contents) {
        contents->strings = (char **)malloc(sizeof(char *[allocated]));
        if (contents->strings)
            contents->allocated = allocated;
        else
            contents->allocated = 0;
        contents->num = 0;
    }
    return contents;
}

static void contents_add(contents_t *contents, char *string)
{
    if (contents->num == contents->allocated) {
        if (contents->allocated)
        {
            char **new_strings = (char **)
                realloc(contents->strings, sizeof(char *[2*contents->allocated]));
            if (!new_strings)
                    return;
            contents->strings = new_strings;
            contents->allocated *= 2;
        } else {
            contents->strings = (char **) malloc(sizeof(char *[1]));
            if (!contents->strings)
                return;
            contents->allocated = 1;
        }
    }
    contents->strings[contents->num] = string;
    contents->num++;
}

static void contents_destruct(contents_t *contents)
{
    free(contents->strings);
    free(contents);
}

static void contents_cat(contents_t *dest, contents_t *src)
{
    int size = src->num;
    if (dest->num+size > dest->allocated) {
        if (dest->allocated)
        {
            dest->strings = (char **)
                realloc(dest->strings, sizeof(char *[dest->allocated+size]));
            dest->allocated += size;
        } else {
            dest->strings = (char **)
                realloc(dest->strings, sizeof(char *[size]));
            dest->allocated = size;
        }
    }
    memcpy(&dest->strings[dest->num], src->strings, sizeof(char *[src->num]));
    dest->num += src->num;
}

static void json_close_object(json_t *object)
{
    switch (object->type) {
        case JSON_ARRAY:
            contents_add(object->contents, strdup("]"));
            break;
        case JSON_DICT:
            contents_add(object->contents, strdup("}"));
            break;
        default:
            ;
    }
}
static contents_t *get_content_and_destroy(json_t *object)
{
    contents_t *contents = object->contents;
    json_close_object(object);
    free(object);
    return contents;
}

json_t *json_dict_new()
{
    json_t *dict = (json_t *)malloc(sizeof(json_t));
    if (dict) {
        dict->type = JSON_DICT;
        dict->contents = contents_new(3);
        contents_add(dict->contents, strdup("{"));
    }
    return dict;
}

void json_dict_add(json_t *dict, char *field, json_t *child)
{
    assert(dict->type == JSON_DICT);

    if (dict->contents->num > 1) {
        contents_add(dict->contents, strdup(","));
    }
    char *field_string;
    if (-1 < asprintf(&field_string, "\"%s\":", field)) {
        contents_add(dict->contents, field_string);
        contents_t *child_contents = get_content_and_destroy(child);
        contents_cat(dict->contents, child_contents);
        contents_destruct(child_contents);
    }
}

json_t *json_array_new()
{
    json_t *array = (json_t *)malloc(sizeof(json_t));
    if (array) {
        array->type = JSON_ARRAY;
        array->contents = contents_new(3);
        contents_add(array->contents, strdup("["));
    }
    return array;
}

void json_array_add(json_t *array, json_t *child)
{
    assert(array && array->type == JSON_ARRAY);
    assert(child);

    if (array->contents->num > 1) {
        contents_add(array->contents, strdup(","));
    }
    contents_t *child_contents = get_content_and_destroy(child);
    contents_cat(array->contents, child_contents);
    contents_destruct(child_contents);
}

void json_array_concat(json_t *dest, json_t *src)
{
    assert(dest && dest->type == JSON_ARRAY);
    assert(src  && src->type  == JSON_ARRAY);

    free(src->contents->strings[0]);
    if (src->contents->num > 1) {
        src->contents->strings[0] = strdup(",");
        contents_cat(dest->contents, src->contents);
    }
    contents_destruct(src->contents);
    free(src);
}

json_t *json_string_new(char *value)
{
    json_t *string = (json_t *)malloc(sizeof(json_t));
    if (string) {
        string->type = JSON_STRING;
        string->contents = contents_new(1);

        char *new_value;
        if (-1 < asprintf(&new_value, "\"%s\"", value))
            contents_add(string->contents, new_value);
    }
    return string;
}

json_t *json_int_new(int value)
{
    json_t *integer = (json_t *)malloc(sizeof(json_t));
    if (integer) {
        integer->type = JSON_INT;
        integer->contents = contents_new(1);

        char *new_value;
        if (-1 < asprintf(&new_value, "%d", value))
            contents_add(integer->contents, new_value);
    }
    return integer;
}

json_t *json_uint_new(unsigned int value)
{
    json_t *uinteger = (json_t *)malloc(sizeof(json_t));
    if (uinteger) {
        uinteger->type = JSON_UINT;
        uinteger->contents = contents_new(1);

        char *new_value;
        if (-1 < asprintf(&new_value, "%u", value))
            contents_add(uinteger->contents, new_value);
    }
    return uinteger;
}

json_t *json_ullint_new(unsigned long long int value)
{
    json_t *ullinteger = (json_t *)malloc(sizeof(json_t));
    if (ullinteger) {
        ullinteger->type = JSON_ULLINT;
        ullinteger->contents = contents_new(1);

        char *new_value;
        if (-1 < asprintf(&new_value, "%llu", value))
            contents_add(ullinteger->contents, new_value);
    }
    return ullinteger;
}

json_t *json_float_new(float value)
{
    json_t *real = (json_t *)malloc(sizeof(json_t));
    if (real) {
        real->type = JSON_FLOAT;
        real->contents = contents_new(1);

        char *new_value;
        if (-1 < asprintf(&new_value, "%f", value))
            contents_add(real->contents, new_value);
    }
    return real;
}

void json_write(FILE *file, json_t *object)
{
    json_close_object(object);
    for (int i = 0; i < object->contents->num; i++) {
        fprintf(file, "%s", object->contents->strings[i]);
    }
}

void json_free(json_t *object)
{
    for (int i = 0; i < object->contents->num; i++) {
        free(object->contents->strings[i]);
    }
    free(object->contents->strings);
    free(object->contents);
    free(object);
}

/* End of JSON functions */
/******************************************************************************/

static char *remove_quote(char *string)
{
    if (string[0] == '\'')
        return strndup(string+1, strrchr(string, '\'') - string-1);
    else
        return strndup(string, strlen(string));
}

static int handle_link(netloc_physical_link_t *link, json_t *json_links)
{
    char *src = link->src->physical_id;
    char *dest = link->dest->physical_id;

    json_t *json_link = json_dict_new();
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_ID,        json_ullint_new(link->id));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_SRC,       json_string_new(src));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_SRC_PORT,  json_int_new(link->ports[0]));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_DST,       json_string_new(dest));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_DST_PORT,  json_int_new(link->ports[1]));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_WIDTH,     json_string_new(link->width));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_SPEED,     json_string_new(link->speed));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_GBITS,     json_float_new(link->gbits));
    json_dict_add(json_link,
            JSON_DRAW_FILE_LINK_OTHER_WAY, json_int_new(link->other_way_id));

    json_t *json_partitions = json_array_new();

    for (unsigned int p = 0; p < netloc_get_num_partitions(link); p++)
    {
        unsigned int partition = netloc_get_partition_id(link, p);
        json_array_add(json_partitions, json_uint_new(partition));
    }
    json_dict_add(json_link, JSON_DRAW_FILE_LINK_PARTITIONS, json_partitions);

    json_array_add(json_links, json_link);

    return NETLOC_SUCCESS;
}

static int handle_edge(netloc_edge_t *edge, json_t *json_edges)
{
    char *src = edge->node->physical_id;
    char *dest = edge->dest->physical_id;

    json_t *json_edge = json_dict_new();

    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_ID, json_int_new(edge->id));
    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_SRC, json_string_new(src));
    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_DST, json_string_new(dest));
    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_GBITS,
                  json_float_new(edge->total_gbits));
    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_OTHER_WAY,
                  json_int_new(edge->other_way->id));

    /* Links */
    json_t *json_links = json_array_new();
    for (unsigned int l = 0; l < netloc_edge_get_num_links(edge); l++)
    {
        netloc_physical_link_t *link = netloc_edge_get_link(edge, l);
        json_array_add(json_links, json_int_new(link->id));
    }
    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_LINKS, json_links);

    /* Partition list */
    json_t *json_partitions = json_array_new();
    for (unsigned int p = 0; p < netloc_get_num_partitions(edge); p++)
    {
        unsigned int partition = netloc_get_partition_id(edge, p);
        json_array_add(json_partitions, json_uint_new(partition));
    }
    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_PARTITIONS, json_partitions);

    /* Subnode edges */
    json_t *json_subedges = json_array_new();
    for (unsigned int s = 0; s < netloc_edge_get_num_subedges(edge); s++)
    {
        netloc_edge_t *subedge = netloc_edge_get_subedge(edge, s);
        json_array_add(json_subedges, json_int_new(subedge->id));
        /* The subedges are already added to the dictionnary. We just need ids */
    }
    json_dict_add(json_edge, JSON_DRAW_FILE_EDGE_SUBEDGES, json_subedges);

    json_array_add(json_edges, json_edge);

    return NETLOC_SUCCESS;
}

static int handle_node(netloc_node_t *node, json_t *json_nodes,
        json_t *json_edges, int merged)
{
    char *id = node->physical_id;
    char *desc = remove_quote(node->description);
    char *hostname = node->hostname;
    size_t topoIdx = node->hwloc_topo_idx;

    json_t *json_node = json_dict_new();
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_ID, json_string_new(id));
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_DESC, json_string_new(desc));
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_HOSTNAME,
                  json_string_new(hostname));
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_HWLOCTOPO,
                  json_int_new(topoIdx));
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_MERGED, json_int_new(merged));

    /* Subnodes */
    json_t *json_subnodes = json_array_new();
    for (unsigned int s = 0; s < netloc_node_get_num_subnodes(node); s++)
    {
        netloc_node_t *subnode = netloc_node_get_subnode(node, s);
        handle_node(subnode, json_nodes, json_edges, 1);
        json_array_add(json_subnodes, json_string_new(subnode->physical_id));
    }
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_SUBNODES, json_subnodes);

    /* Edges */
    json_t *json_edge_ids = json_array_new();
    netloc_edge_t *edge, *edge_tmp;
    netloc_node_iter_edges(node, edge, edge_tmp) {
        json_array_add(json_edge_ids, json_int_new(edge->id));
        handle_edge(edge, json_edges);
    }
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_EDGES, json_edge_ids);

    /* Partitions */
    json_t *json_partitions = json_array_new();
    for (unsigned int p = 0; p < netloc_get_num_partitions(node); p++)
    {
        unsigned int partition = netloc_get_partition_id(node, p);
        json_array_add(json_partitions, json_uint_new(partition));
    }
    json_dict_add(json_node, JSON_DRAW_FILE_NODE_PARTITIONS, json_partitions);

    if (netloc_node_is_host(node)) {
        json_dict_add(json_node, JSON_DRAW_FILE_NODE_TYPE,
                      json_string_new("host"));
    }
    else if (netloc_node_is_switch(node)) {
        json_dict_add(json_node, JSON_DRAW_FILE_NODE_TYPE,
                      json_string_new("switch"));
    }
    else {
        json_dict_add(json_node, JSON_DRAW_FILE_NODE_TYPE,
                      json_string_new("unknown"));
    }

    json_array_add(json_nodes, json_node);

    free(desc);
    return NETLOC_SUCCESS;
}

static int handle_path(netloc_node_t *node, json_t *json_paths)
{
    char *id = node->physical_id;

    json_t *json_node_paths = json_dict_new();
    json_dict_add(json_node_paths, JSON_DRAW_FILE_PATH_ID, json_string_new(id));

    /* Paths */
    json_t *json_path_list = json_array_new();
    netloc_path_t *path, *path_tmp;
    netloc_node_iter_paths(node, path, path_tmp) {
        json_t *json_node_path = json_dict_new();
        json_dict_add(json_node_path, JSON_DRAW_FILE_PATH_ID,
                json_string_new(path->dest_id));

        json_t *json_links = json_array_new();
        netloc_physical_link_t **plink;
        netloc_path_iter_links(path,plink) {
            json_array_add(json_links, json_int_new((*plink)->id));
        }
        json_dict_add(json_node_path, JSON_DRAW_FILE_PATH_LINKS,
                json_links);
        json_array_add(json_path_list, json_node_path);
    }
    json_dict_add(json_node_paths, JSON_DRAW_FILE_PATHS, json_path_list);

    json_array_add(json_paths, json_node_paths);

    return NETLOC_SUCCESS;
}

static int handle_partitions(netloc_partition_t *partition,
                             json_t *json_partitions)
{
    json_array_add(json_partitions, json_string_new(partition->name));
    return NETLOC_SUCCESS;
}

static int handle_topos(netloc_topology_t *topology, json_t *json_topos)
{
    char *ptopo, *basename_topo;
    netloc_topology_iter_name_hwloctopos(topology, ptopo) {
        basename_topo = basename(ptopo);
        /* Not a diff file, so extension must be .xml */
        ptopo    = strrchr(basename_topo, '.');
        ptopo[0] = '\0';
        json_array_add(json_topos, json_string_new(basename_topo));
    }
    return NETLOC_SUCCESS;
}

static int write_json(netloc_topology_t *topology, FILE *output)
{
    json_t *json_root = json_dict_new();
    json_t *json_nodes = json_array_new();
    json_t *json_edges = json_array_new();
    json_t *json_nodes_extra = json_array_new();
    json_t *json_edges_extra = json_array_new();

    /* Graph type */
    json_dict_add(json_root, JSON_DRAW_FILE_GRAPH_TYPE,
                  json_string_new("tree"));

    /* Physical links */
    json_t *json_links = json_array_new();
    netloc_physical_link_t *link, *link_tmp;
    HASH_ITER(hh, topology->physical_links, link, link_tmp) {
        handle_link(link, json_links);
    }

    /* Paths */
    json_t *json_paths = json_array_new();
    netloc_node_t *node, *node_tmp;
    HASH_ITER(hh, topology->nodes, node, node_tmp) {
        handle_path(node, json_paths);
        /* extra+structural nodes */
        if (!netloc_get_num_partitions(node)
            && (!node->subnodes || node->nsubnodes))
            handle_node(node, json_nodes_extra, json_edges_extra, 0);
    }

    /* Partitions */
    json_t *json_partitions = json_array_new();
    netloc_partition_t *partition, *partition_tmp __netloc_attribute_unused;
    netloc_topology_iter_partitions(topology, partition, partition_tmp) {
        handle_partitions(partition, json_partitions);
        /* Nodes */
        netloc_partition_iter_nodes(partition, pnode) {
            if (partition->id == netloc_get_partition_id(*pnode, 0))
                handle_node(*pnode, json_nodes, json_edges, 0);
        }
    }

    json_array_concat(json_nodes, json_nodes_extra);
    json_array_concat(json_edges, json_edges_extra);
    json_dict_add(json_root, JSON_DRAW_FILE_NODES, json_nodes);
    json_dict_add(json_root, JSON_DRAW_FILE_EDGES, json_edges);
    json_dict_add(json_root, JSON_DRAW_FILE_LINKS, json_links);
    json_dict_add(json_root, JSON_DRAW_FILE_PATHS, json_paths);
    json_dict_add(json_root, JSON_DRAW_FILE_PARTITIONS, json_partitions);

    /* Hwloc topologies */
    json_t *json_topos = json_array_new();
    handle_topos(topology, json_topos);
    json_dict_add(json_root, JSON_DRAW_FILE_HWLOCTOPOS, json_topos);

    json_write(output, json_root);
    json_free(json_root);

    return NETLOC_SUCCESS;
}

static int netloc_to_json_draw(netloc_topology_t *topology)
{
    int ret;
    FILE *output;
    char *node_uri = topology->topopath;
    int basename_len = strlen(node_uri)-10;
    char *basename = (char *)malloc(sizeof(char[basename_len + 1]));
    char *draw;

    netloc_topology_read_hwloc(topology, 0, NULL);

    strncpy(basename, node_uri, basename_len);
    basename[basename_len] = '\0';

    if (0 > asprintf(&draw, "%s-%s.json", basename, "draw"))
        draw = NULL;
    output = fopen(draw, "w");
    free(draw);
    if (output == NULL) {
        perror("fopen: ");
        ret = NETLOC_ERROR;
        goto ERROR;
    }

    ret = write_json(topology, output);

    fclose(output);
ERROR:
    free(basename);

    return ret;
}

static char *read_param(int *argc, char ***argv)
{
    if (!*argc)
        return NULL;

    char *ret = **argv;
    (*argv)++;
    (*argc)--;

    return ret;
}

void help(char *name, FILE *f)
{
    fprintf(f, "Usage: %s <path to topology directory>\n", name);
}

int main(int argc, char **argv)
{
    char *prog_name = basename(argv[0]);

    if (argc != 2) {
        help(prog_name, stderr);
        return EXIT_FAILURE;
    }
    read_param(&argc, &argv);

    char *param;
    param = read_param(&argc, &argv);

    char *netlocpath;
    if (!strcmp(param, "--help")) {
        help(prog_name, stdout);
        return EXIT_SUCCESS;
    } else {
        netlocpath = param;
    }

    DIR *netlocdir = opendir(netlocpath);
    if (!netlocdir) {
        fprintf(stderr, "Error: Cannot open the directory <%s>.\n", netlocpath);
        return NETLOC_ERROR;
    }

    struct dirent *dir_entry = NULL;
    while ((dir_entry = readdir(netlocdir)) != NULL) {
        char *topopath;

#ifdef _DIRENT_HAVE_D_TYPE
        /* Skip directories if the filesystem returns a useful d_type.
         * Otherwise, continue and let the actual opening will fail later.
         */
        if( DT_DIR == dir_entry->d_type ) {
            continue;
        }
#endif

        /* Skip if does not end in .xml extension */
        if( NULL == strstr(dir_entry->d_name, "-nodes.xml") ) {
            continue;
        }

        if (0 > asprintf(&topopath, "%s/%s", netlocpath, dir_entry->d_name))
            topopath = NULL;

        netloc_topology_t *topology;
        int ret = netloc_topology_xml_load(topopath, &topology);
        free(topopath);
        if (NETLOC_SUCCESS != ret) {
            fprintf(stderr, "Error: netloc_topology_construct failed\n");
            return ret;
        }

        netloc_edge_reset_uid();

        netloc_to_json_draw(topology);

        netloc_topology_destruct(topology);
    }
    closedir(netlocdir);

    return EXIT_SUCCESS;
}
