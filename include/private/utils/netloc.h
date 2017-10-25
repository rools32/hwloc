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

#ifndef _UTILS_NETLOC_H_
#define _UTILS_NETLOC_H_

#include <private/autogen/config.h>
#include <private/netloc.h>
#include <netloc/uthash.h>
#include <netloc/utarray.h>

#define MAX_STR 20

struct node_t;
typedef struct node_t node_t;
struct edge_t;
typedef struct edge_t edge_t;
struct physical_link_t;
typedef struct physical_link_t physical_link_t;

struct edge_t {
    UT_hash_handle hh;         /* makes this structure hashable */
    char dest[MAX_STR];        /* key */
    float total_gbits;
    UT_array *physical_link_idx;
    int *partitions;
    edge_t *reverse_edge;
    UT_array *subedges; /* Hash table of subedges */
};

struct node_t {
    UT_hash_handle hh;         /* makes this structure hashable */
    char physical_id[MAX_STR]; /* key */
    long logical_id;
    netloc_node_type_t type;
    char *description;
    edge_t *edges;
    int main_partition;
    char *hostname;
    int *partitions;
    UT_array *physical_links;
    node_t *subnodes; /* Hash table of subnodes */
};
extern node_t *nodes;

extern UT_array *partitions;

struct physical_link_t {
    unsigned long long int int_id;
    int ports[2];
    node_t *dest;
    char *width;
    char *speed;
    float gbits;
    char *description;
    int *partitions;
    physical_link_t *other_link;
    edge_t *parent_edge;
    node_t *parent_node;
};

static UT_icd physical_link_icd = { sizeof(physical_link_t), NULL, NULL, NULL };

/* Route tables */
typedef struct {
    UT_hash_handle hh  ;       /* makes this structure hashable */
    char physical_id[MAX_STR]; /* key */
    int port;
} route_dest_t;
typedef struct {
    UT_hash_handle hh;         /* makes this structure hashable */
    char physical_id[MAX_STR]; /* key */
    route_dest_t *dest;
} route_source_t;
extern route_source_t *routes;

/* Paths tables */
typedef struct {
    UT_hash_handle hh;         /* makes this structure hashable */
    char physical_id[MAX_STR]; /* key */
    node_t *node;
    UT_array *links;
} path_dest_t;
typedef struct {
    UT_hash_handle hh;         /* makes this structure hashable */
    char physical_id[MAX_STR]; /* key */
    node_t *node;
    path_dest_t *dest;
} path_source_t;
extern path_source_t *paths;

static inline int node_is_virtual(node_t *node)
{
    return (NULL != node->subnodes);
}

static inline int edge_is_virtual(edge_t *edge)
{
    return (NULL != edge->subedges);
}

extern int
netloc_write_into_xml_file(node_t *nodes, const UT_array *partitions,
                           const char *subnet, const char *path,
                           const char *hwlocpath,
                           const netloc_network_type_t transportType);

#endif /* _UTILS_NETLOC_H_ */
