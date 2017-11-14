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

/*
 * This file provides general function to translate from utils_*_t
 * datatypes to netloc_*_t.
 */

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <private/netloc.h>
#include <netloc.h>
#include <private/autogen/config.h>
#include <private/utils/netloc.h>

#include <netloc/uthash.h>
#include <netloc/utarray.h>

static void create_node(const node_t *node, netloc_node_t *topo_node,
                        netloc_network_explicit_t *topology,
                        netloc_partition_t *extra_part)
{
    assert(topo_node);
    /* Copy attributes */
    topo_node->type = node->type;
    topo_node->logical_id = node->logical_id;
    strncpy(topo_node->physical_id, node->physical_id, 20);
    if (node->hostname) {
        topo_node->hostname =
            (char *) malloc(sizeof(char[strlen(node->hostname) + 1]));
        strcpy(topo_node->hostname, node->hostname);
    }
    if (node->description) {
        topo_node->description =
            (char *) malloc(sizeof(char[strlen(node->description) + 1]));
        strcpy(topo_node->description, node->description);
    }
    /* Add the node to the topology */
    HASH_ADD_STR(topology->nodes, physical_id, topo_node);
    if (node->hostname) {
        HASH_ADD_KEYPTR(hh2, topology->nodesByHostname, topo_node->hostname,
                        strlen(topo_node->hostname), topo_node);
    }
    /* Add potential subnodes */
    unsigned int nsubnodes = HASH_COUNT(node->subnodes);
    if (nsubnodes) {
        unsigned int i = 0;
        node_t *subnode, *subnode_tmp;
        topo_node->nsubnodes = nsubnodes;
        topo_node->subnodes =
            (netloc_node_t **) malloc(sizeof(netloc_node_t *[nsubnodes]));
        HASH_ITER(hh, node->subnodes, subnode, subnode_tmp) {
            netloc_node_t *topo_subnode = netloc_node_construct();
            create_node(subnode, topo_subnode, topology, extra_part);
            topo_subnode->virtual_node = topo_node;
            topo_node->subnodes[i] = topo_subnode;
            ++i;
        }
    }
    /* Add partition */
    netloc_partition_t *topo_part, *topo_part_tmp;
    HASH_ITER(hh, topology->partitions, topo_part, topo_part_tmp) {
        if (node->partitions[topo_part->id]) {
            utarray_push_back(topo_part->nodes, &topo_node);
            utarray_push_back(topo_node->partitions, &topo_part);
        }
    }
    if (!utarray_len(topo_node->partitions)) {
        /* Add to /extra+structural/ if needed */
        utarray_push_back(extra_part->nodes, &topo_node);
        utarray_push_back(topo_node->partitions, &extra_part);
    }
}

static netloc_edge_t *
create_edges(const edge_t *edge, netloc_network_explicit_t *topology,
             netloc_partition_t *extra_part)
{
    netloc_edge_t *topo_edge = netloc_edge_construct();
    if (!topo_edge)
        return NULL;
    /* Copy attributes */
    topo_edge->total_gbits = edge->total_gbits;
    assert(edge);
    assert(edge->reverse_edge);
    HASH_FIND_STR(topology->nodes, edge->dest, topo_edge->dest);
    assert(topo_edge->dest);
    HASH_FIND_STR(topology->nodes, edge->reverse_edge->dest, topo_edge->node);
    assert(topo_edge->node);
    /* Add topo_edge to its topo_node */
    HASH_ADD_STR(topo_edge->node->edges, dest->physical_id, topo_edge);
    /* Check if reverse edge is already defined */
    HASH_FIND_STR(topo_edge->dest->edges, topo_edge->node->physical_id,
                  topo_edge->other_way);
    if (topo_edge->other_way)
        topo_edge->other_way->other_way = topo_edge;
    unsigned int nsubedges =
        edge_is_virtual(edge) ? utarray_len(edge->subedges) : (unsigned) 0;
    if (nsubedges) {
        topo_edge->nsubedges = nsubedges;
        topo_edge->subnode_edges =
            (netloc_edge_t **) malloc(sizeof(netloc_edge_t *[nsubedges]));
        assert(topo_edge->subnode_edges);
        for (unsigned int i = 0; i < utarray_len(edge->subedges); ++i) {
            edge_t *subedge = *(edge_t **) utarray_eltptr(edge->subedges, i);
            netloc_edge_t *topo_subedge =
                create_edges(subedge, topology, extra_part);
            assert(topo_subedge);
            topo_edge->subnode_edges[i] = topo_subedge;
        }
    }
    /* Add partition */
    netloc_partition_t *topo_part, *topo_part_tmp;
    HASH_ITER(hh, topology->partitions, topo_part, topo_part_tmp) {
        if (edge->partitions[topo_part->id]) {
            utarray_push_back(topo_part->edges, &topo_edge);
            utarray_push_back(topo_edge->partitions, &topo_part);
        }
    }
    if (!utarray_len(topo_edge->partitions)) {
        /* Add to /extra+structural/ if needed */
        utarray_push_back(extra_part->edges, &topo_edge);
        utarray_push_back(topo_edge->partitions, &extra_part);
    }
    return topo_edge;
}

static inline netloc_physical_link_t *
create_physical_link(const physical_link_t *link,
                     netloc_network_explicit_t *topology)
{
    netloc_physical_link_t *topo_link = netloc_physical_link_construct();
    if (!topo_link)
        return NULL;
    /* Copy attributes */
    topo_link->id = link->int_id;
    topo_link->gbits = link->gbits;
    topo_link->width = strdup(link->width);
    topo_link->speed = strdup(link->speed);
    topo_link->description = strdup(link->description);
    topo_link->other_way_id = link->other_link->int_id;
    memcpy(topo_link->ports, link->ports, sizeof(int[2]));
    HASH_FIND_STR(topology->nodes, link->parent_node->physical_id,
                  topo_link->src);
    assert(topo_link->src);
    HASH_FIND_STR(topology->nodes, link->dest->physical_id, topo_link->dest);
    assert(topo_link->dest);
    HASH_FIND_STR(topo_link->src->edges, link->parent_edge->dest,
                  topo_link->edge);
    assert(topo_link->edge);
    HASH_FIND(hh, topology->physical_links, &topo_link->other_way_id,
              sizeof(unsigned long long int), topo_link->other_way);
    if (topo_link->other_way)
        topo_link->other_way->other_way = topo_link;
    /* Add link to the proper structures */
    HASH_ADD(hh, topology->physical_links, id, sizeof(unsigned long long int),
             topo_link);
    utarray_push_back(topo_link->src->physical_links, &topo_link);
    if (topo_link->src->nsubnodes) {
        /* Add link to the parent virtual node in case of a subnode */
        utarray_push_back(topo_link->src->virtual_node->physical_links,
                          &topo_link);
    }
    utarray_push_back(topo_link->edge->physical_links, &topo_link);
    /* Add partitions */
    utarray_concat(topo_link->partitions, topo_link->edge->partitions);
    return topo_link;
}

netloc_network_explicit_t *
create_netloc_network_explicit(const char *subnet, const char *hwlocpath,
                               node_t *nodes, const UT_array *partitions)
{
    unsigned int npartitions = utarray_len(partitions);
    netloc_network_explicit_t *topology = netloc_network_explicit_construct();
    if (!topology)
        return topology;

    topology->subnet_id = strdup(subnet);
    topology->hwloc_dir_path = strdup(hwlocpath);
    topology->parent.transport_type = NETLOC_NETWORK_TYPE_INFINIBAND;
    /* Create partitions */
    netloc_partition_t *extra_part, *topo_partition;
    for (unsigned p = 0; p < npartitions; ++p) {
        partition_t *partition = *(partition_t **)utarray_eltptr(partitions, p);
        topo_partition = netloc_partition_construct(p, partition->name);
        HASH_ADD_STR(topology->partitions, name, topo_partition);
    }
    extra_part = netloc_partition_construct(npartitions, "/extra+structural/");
    /* Add nodes */
    node_t *node, *node_tmp;
    HASH_ITER(hh, nodes, node, node_tmp) {
        netloc_node_t *topo_node = netloc_node_construct();
        create_node(node, topo_node, topology, extra_part);
    }
    /* Add edges */
    HASH_ITER(hh, nodes, node, node_tmp) {
        edge_t *edge, *edge_tmp;
        HASH_ITER(hh, node->edges, edge, edge_tmp) {
            create_edges(edge, topology, extra_part);
        }
    }
    /* Add physical links */
    HASH_ITER(hh, nodes, node, node_tmp) {
        edge_t *edge, *edge_tmp;
        HASH_ITER(hh, node->edges, edge, edge_tmp) {
            if (edge_is_virtual(edge))
                continue;
            for (unsigned i = 0; i<utarray_len(edge->physical_link_idx); ++i) {
                unsigned int id = *(unsigned int *)
                    utarray_eltptr(edge->physical_link_idx, i);
                physical_link_t *link = (physical_link_t *)
                    utarray_eltptr(node->physical_links, id);
                create_physical_link(link, topology);
            }
        }
    }
    /* Add physical links to virtual edges */
    netloc_node_t *topo_node, *topo_node_tmp;
    HASH_ITER(hh, topology->nodes, topo_node, topo_node_tmp) {
        netloc_edge_t *topo_edge, *topo_edge_tmp;
        HASH_ITER(hh, topo_node->edges, topo_edge, topo_edge_tmp) {
            for (unsigned i = 0; i < topo_edge->nsubedges; ++i)
                utarray_concat(topo_edge->physical_links,
                               topo_edge->subnode_edges[i]->physical_links);
        }
    }
    HASH_ADD_STR(topology->partitions, name, extra_part);
    return topology;
}
