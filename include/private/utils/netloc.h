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

struct utils_partition_t;
typedef struct utils_partition_t utils_partition_t;
struct utils_node_t;
typedef struct utils_node_t utils_node_t;
struct utils_edge_t;
typedef struct utils_edge_t utils_edge_t;
struct utils_physical_link_t;
typedef struct utils_physical_link_t utils_physical_link_t;

/******************************************************************************/
/* New abstract datatype for netloc */

struct netloc_new_partition_t;
typedef struct netloc_new_partition_t netloc_new_partition_t;

struct netloc_new_partition_t {
    /* Topology description */
    netloc_topology_t *topology;

    /* Complete topology, containing every nodes and edges */
    netloc_network_explicit_t *full_topo;
};

/******************************************************************************/

struct utils_edge_t {
    UT_hash_handle hh;         /* makes this structure hashable */
    char dest[MAX_STR];        /* key */
    float total_gbits;
    UT_array *physical_link_idx;
    int *partitions;
    utils_edge_t *reverse_edge;
    UT_array *subedges; /* Hash table of subedges */
};

struct utils_node_t {
    UT_hash_handle hh;         /* makes this structure hashable */
    char physical_id[MAX_STR]; /* key */
    long logical_id;
    netloc_node_type_t type;
    char *description;
    utils_edge_t *edges;
    int main_partition;
    char *hostname;
    int *partitions;
    UT_array *physical_links;
    utils_node_t *subnodes; /* Hash table of subnodes */
};

struct utils_partition_t {
    char *name;
    netloc_arch_t *arch;  /* Abstract topology */
    UT_array *nodes;
};

struct utils_physical_link_t {
    unsigned long long int int_id;
    int ports[2];
    utils_node_t *dest;
    char *width;
    char *speed;
    float gbits;
    char *description;
    int *partitions;
    utils_physical_link_t *other_link;
    utils_edge_t *parent_edge;
    utils_node_t *parent_node;
};

static UT_icd utils_physical_link_icd =
    { sizeof(utils_physical_link_t), NULL, NULL, NULL };

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
    utils_node_t *node;
    UT_array *links;
} path_dest_t;
typedef struct {
    UT_hash_handle hh;         /* makes this structure hashable */
    char physical_id[MAX_STR]; /* key */
    utils_node_t *node;
    path_dest_t *dest;
} path_source_t;
extern path_source_t *paths;

static inline int node_is_virtual(const utils_node_t *node)
{
    return (NULL != node->subnodes);
}

static inline int edge_is_virtual(const utils_edge_t *edge)
{
    return (NULL != edge->subedges);
}

extern int
netloc_write_into_xml_file(utils_node_t *nodes, UT_array *partitions,
                           const char *subnet, const char *path,
                           const char *hwlocpath,
                           const netloc_network_type_t transportType);

#endif /* _UTILS_NETLOC_H_ */
