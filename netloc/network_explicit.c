/*
 * Copyright © 2013-2014 University of Wisconsin-La Crosse.
 *                         All rights reserved.
 * Copyright © 2016-2017 Inria.  All rights reserved.
 *
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 * See COPYING in top-level directory.
 *
 * $HEADER$
 */

#include <stdio.h>

#include <private/netloc.h>

netloc_network_explicit_t *netloc_network_explicit_construct()
{
    netloc_network_explicit_t *topology = NULL;

    /*
     * Allocate Memory
     */
    topology = (netloc_network_explicit_t *)
        calloc(1, sizeof(netloc_network_explicit_t));
    if( NULL == topology ) {
        fprintf(stderr, "ERROR: Memory error: topology cannot be allocated\n");
        return NULL;
    }

    /*
     * Initialize the structure
     */
    topology->nodes           = NULL;
    topology->physical_links  = NULL;
    topology->partitions      = NULL;
    topology->type            = NETLOC_TOPOLOGY_TYPE_INVALID;
    topology->nodesByHostname = NULL;
    topology->hwloc_topos     = NULL;
    topology->hwlocpaths      = NULL;
    topology->transport_type  = NETLOC_NETWORK_TYPE_INVALID;

    return topology;
}

int netloc_network_explicit_destruct(netloc_network_explicit_t *topology)
{
    /*
     * Sanity Check
     */
    if( NULL == topology ) {
        fprintf(stderr, "Error: Detaching from a NULL pointer\n");
        return NETLOC_ERROR;
    }

    if (topology->topopath)
        free(topology->topopath);
    if (topology->subnet_id)
        free(topology->subnet_id);

    /** Partition List */
    /* utarray_free(topology->partitions); */
    netloc_partition_t *part, *part_tmp;
    HASH_ITER(hh, topology->partitions, part, part_tmp) {
        HASH_DEL(topology->partitions, part);
        netloc_partition_destruct(part);
    }

    /* Nodes */
    netloc_node_t *node, *node_tmp;
    HASH_ITER(hh2, topology->nodesByHostname, node, node_tmp) {
        HASH_DELETE(hh2, topology->nodesByHostname, node);
    }
    netloc_network_explicit_iter_nodes(topology, node, node_tmp) {
        HASH_DEL(topology->nodes, node);
        netloc_node_destruct(node);
    }

    /** Physical links */
    netloc_physical_link_t *link, *link_tmp;
    HASH_ITER(hh, topology->physical_links, link, link_tmp) {
        HASH_DEL(topology->physical_links, link);
        netloc_physical_link_destruct(link);
    }

    /** Hwloc topology List */
    for (unsigned int t = 0; t < topology->nb_hwloc_topos; ++t) {
        if (topology->hwlocpaths && topology->hwlocpaths[t])
            free(topology->hwlocpaths[t]);
        if (topology->hwloc_topos && topology->hwloc_topos[t])
            hwloc_topology_destroy(topology->hwloc_topos[t]);
    }

    if (topology->hwlocpaths)
        free(topology->hwlocpaths);
    if (topology->hwloc_topos)
        free(topology->hwloc_topos);
    if (topology->hwloc_dir_path)
        free(topology->hwloc_dir_path);

    free(topology);

    return NETLOC_SUCCESS;
}

int
netloc_network_explicit_find_reverse_edges(netloc_network_explicit_t *topology)
{
    netloc_node_t *node, *node_tmp;
    netloc_network_explicit_iter_nodes(topology, node, node_tmp) {
        netloc_edge_t *edge, *edge_tmp;
        netloc_node_iter_edges(node, edge, edge_tmp) {
            netloc_node_t *dest = edge->dest;
            if (dest > node) {
                netloc_edge_t *reverse_edge;
                HASH_FIND_PTR(dest->edges, &node, reverse_edge);
                if (reverse_edge == NULL) {
                    return NETLOC_ERROR;
                }
                edge->other_way = reverse_edge;
                reverse_edge->other_way = edge;
            }
        }
    }
    return NETLOC_SUCCESS;
}
