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
 * This file provides general function to generate XML topology files
 * after reworking the explicit graph in order to merge into virtual
 * nodes when possible.
 */

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <private/netloc.h>
#include <netloc.h>
#include <private/autogen/config.h>
#include <private/utils/netloc.h>

#include <netloc/uthash.h>
#include <netloc/utarray.h>

extern int
netloc_write_xml_file(node_t *nodes, const UT_array *partitions,
                      const char *subnet, const char *path,
                      const char *hwlocpath,
                      const netloc_network_type_t transportType);
extern netloc_network_explicit_t *
create_netloc_network_explicit(const char *subnet, const char *hwlocpath,
                               node_t *nodes, const UT_array *partitions);

static int get_virtual_id(char *id)
{
    static unsigned int virtual_id = 0;
    sprintf(id, "virtual%012u", ++virtual_id);
    return 0;
}

static int sort_by_dest(edge_t *a, edge_t *b)
{
    return strncmp(a->dest, b->dest, MAX_STR);
}

/**
 * Merge \ref edge going from \ref node to \ref dest_node into \ref
 * virtual_edge going from \ref virtual_node to \ref dest_node .
 *
 * At this point, \ref virtual_edge is not part of \ref
 * virtual_node->edges . \ref node is still part of \ref nodes and
 * \ref edge is still part of \ref node->edges . \ref node is always
 * of SW type.
 */
static inline void edge_merge_into(node_t *virtual_node, edge_t *virtual_edge,
                                   node_t *node, edge_t *edge, node_t *dest_node,
                                   const unsigned int nparts)
{
    /* Change corresponding edge in reverse */
    edge_t *reverse_edge, *virtual_reverse_edge;
    assert(dest_node);
    HASH_FIND_STR(dest_node->edges, node->physical_id, reverse_edge);
    assert(reverse_edge);
    HASH_DEL(dest_node->edges, reverse_edge);
    /* Check if the virtual_reverse_node is already defined */
    HASH_FIND_STR(dest_node->edges, virtual_node->physical_id, virtual_reverse_edge);
    if (0 != strncmp("virtual", dest_node->physical_id, 7)) {
        if (!virtual_reverse_edge) {
            /* No previous virtual_reverse_edge */
            virtual_reverse_edge = (edge_t *)malloc(sizeof(edge_t));
            strncpy(virtual_reverse_edge->dest, virtual_node->physical_id, MAX_STR);
            virtual_reverse_edge->total_gbits = 0;
            virtual_reverse_edge->reverse_edge = virtual_edge;
            virtual_reverse_edge->partitions = calloc(nparts, sizeof(int));
            utarray_new(virtual_reverse_edge->physical_link_idx, &ut_int_icd);
            utarray_new(virtual_reverse_edge->subedges, &ut_ptr_icd);
            HASH_ADD_STR(dest_node->edges, dest, virtual_reverse_edge);
            virtual_edge->reverse_edge = virtual_reverse_edge;
        }
        /* Merge reverse_edge into virtual_reverse_edge */
        utarray_push_back(virtual_reverse_edge->subedges, &reverse_edge);
        /* Merge edge into virtual_edge */
        utarray_push_back(virtual_edge->subedges, &edge);
    } else {
        assert(virtual_reverse_edge);
        /* Virtual to virtual: less updates to be done */
        /* Merge into reverse virtual */
        utarray_concat(virtual_reverse_edge->subedges, reverse_edge->subedges);
        /* Merge into virtual */
        utarray_concat(virtual_edge->subedges, edge->subedges);
    }
    /* Common merging operations */
    utarray_concat(virtual_reverse_edge->physical_link_idx,
                   reverse_edge->physical_link_idx);
    virtual_reverse_edge->total_gbits += reverse_edge->total_gbits;
    virtual_edge->total_gbits += edge->total_gbits;
    /* Set partitions */
    for (unsigned int p = 0; p < nparts; ++p) {
        virtual_edge->partitions[p] |= edge->partitions[p];
        virtual_reverse_edge->partitions[p] |= reverse_edge->partitions[p];
    }
    /* Add offset to each physical_link index */
    unsigned int offset =
        utarray_len(virtual_node->physical_links) -
        utarray_len(node->physical_links);
    unsigned int num_links = utarray_len(edge->physical_link_idx);
    for (unsigned int l = 0; l < num_links; l++) {
        unsigned int link_idx = *(unsigned int *)
            utarray_eltptr(edge->physical_link_idx, l);
        link_idx += offset;
        utarray_push_back(virtual_edge->physical_link_idx, &link_idx);
#ifdef NETLOC_DEBUG
        physical_link_t *link = (physical_link_t *)
            utarray_eltptr(virtual_node->physical_links, link_idx);
        assert(0 != *(int*)(link->dest));
        if (dest_node->subnodes) {
            node_t*subnode;
            HASH_FIND_STR(dest_node->subnodes, link->parent_edge->dest, subnode);
            assert(subnode);
        } else {
            assert(!strncmp(link->parent_edge->dest, dest_node->physical_id,
                            MAX_STR));
        }
#endif /* NETLOC_DEBUG */
    }
    if (!strncmp("virtual", dest_node->physical_id, 7)) {
        /* Destroy now useless reverse edges */
        utarray_free(reverse_edge->physical_link_idx);
        utarray_free(reverse_edge->subedges);
        free(reverse_edge->partitions);
        free(reverse_edge);
    }
}

static inline int find_similar_nodes(node_t *nodes, const unsigned int nparts)
{
    int ret = NETLOC_ERROR;
    /* Build edge lists by node */
    int num_nodes = HASH_COUNT(nodes);
    node_t **switch_nodes =
        (node_t **)malloc(sizeof(node_t *[num_nodes]));
    node_t ***edgedest_by_node =
        (node_t ***)malloc(sizeof(node_t **[num_nodes]));
    unsigned int *num_edges_by_node =
        (unsigned int *)malloc(sizeof(unsigned int [num_nodes]));
    node_t *node, *node_tmp;
    int idx = -1;
    HASH_ITER(hh, nodes, node, node_tmp) {
        idx++;
        if (NETLOC_NODE_TYPE_HOST == node->type) {
            switch_nodes[idx] = NULL;
            num_edges_by_node[idx] = 0;
            edgedest_by_node[idx] = NULL;
            continue;
        }
        unsigned int num_edges = HASH_COUNT(node->edges);
        switch_nodes[idx] = node;
        num_edges_by_node[idx] = num_edges;
        edgedest_by_node[idx] = (node_t **)malloc(sizeof(node_t *[num_edges]));
        edge_t *edge, *edge_tmp;
        int edge_idx = 0;
        HASH_SORT(node->edges, sort_by_dest);
        netloc_node_iter_edges(node, edge, edge_tmp) {
            HASH_FIND_STR(nodes, edge->dest, edgedest_by_node[idx][edge_idx]);
            assert(edgedest_by_node[idx][edge_idx]);
            edge_idx++;
        }
    }

    /* We compare the edge lists to find similar nodes */
    for (int nodeIdx = 0; nodeIdx < num_nodes - 1; nodeIdx++) {
        node_t *node1 = switch_nodes[nodeIdx];
        node_t *virtual_node = NULL;

        for (int nodeCmpIdx = nodeIdx + 1; node1 && nodeCmpIdx < num_nodes;
             nodeCmpIdx++) {

            node_t *node2 = switch_nodes[nodeCmpIdx];

            int equal = node2
                && num_edges_by_node[nodeIdx] == num_edges_by_node[nodeCmpIdx];

            /* Check if the destinations are the same */
            for (unsigned i = 0; equal && i < num_edges_by_node[nodeIdx]; i++) {
                if (edgedest_by_node[nodeIdx][i]
                    != edgedest_by_node[nodeCmpIdx][i])
                    equal = 0;
            }

            /* If we have similar nodes */
            if (equal) {
                /* We create a new virtual node to contain all of them */
                if (!virtual_node) {
                    /* virtual_node = netloc_node_construct(); */
                    virtual_node = (node_t *)calloc(1, sizeof(node_t));
                    get_virtual_id(virtual_node->physical_id);
                    virtual_node->description = strdup(virtual_node->physical_id);

                    virtual_node->partitions = calloc(nparts, sizeof(int));
                    for (unsigned int p = 0; p < nparts; ++p)
                        virtual_node->partitions[p] |= node1->partitions[p];

                    virtual_node->type = node1->type;
                    virtual_node->subnodes = NULL;
                    utarray_new(virtual_node->physical_links, &physical_link_icd);

                    /* add physical_links */
                    utarray_concat(virtual_node->physical_links, node1->physical_links);

                    /* Initialize destination for virtual edge */
                    for (unsigned i = 0; i < num_edges_by_node[nodeIdx]; i++) {
                        edge_t *edge1, *virtual_edge;
                        node_t *node_dest = edgedest_by_node[nodeIdx][i];
                        HASH_FIND_STR(node1->edges, node_dest->physical_id, edge1);
                        assert(edge1);
                        if (!strncmp("virtual", node_dest->physical_id, 7)) {
                            /* Reuse already defined virtual edge */
                            /* Transfert virtual edge */
                            HASH_DEL(node1->edges, edge1);
                            HASH_ADD_STR(virtual_node->edges, dest, edge1);
                            /* Change reverse */
                            edge1 = edge1->reverse_edge;
                            HASH_DEL(node_dest->edges, edge1);
                            strncpy(edge1->dest, virtual_node->physical_id, MAX_STR);
                            HASH_ADD_STR(node_dest->edges, dest, edge1);
                        } else {
                            /* Create new virtual edge */
                            virtual_edge = (edge_t *)calloc(1, sizeof(edge_t));
                            strncpy(virtual_edge->dest, node_dest->physical_id, MAX_STR);
                            virtual_edge->partitions = calloc(nparts, sizeof(int));
                            virtual_edge->total_gbits = 0;
                            utarray_new(virtual_edge->subedges, &ut_ptr_icd);
                            utarray_new(virtual_edge->physical_link_idx, &ut_int_icd);
                            edge_merge_into(virtual_node, virtual_edge, node1, edge1,
                                            node_dest, nparts);
                            HASH_DEL(node1->edges, edge1);
                            HASH_ADD_STR(virtual_node->edges, dest, virtual_edge);
                        }
                    }
                    /* Remove node from nodes hashtable to add it to the virtual_node subnodes */
                    HASH_DEL(nodes, node1);
                    HASH_ADD_STR(virtual_node->subnodes, physical_id, node1);
                    /* Add virtual_node to nodes hashtable */
                    HASH_ADD_STR(nodes, physical_id, virtual_node);
                }

                /* add physical_links */
                utarray_concat(virtual_node->physical_links, node2->physical_links);

                for (unsigned int p = 0; p < nparts; ++p)
                    virtual_node->partitions[p] |= node2->partitions[p];

                for (unsigned i = 0; i < num_edges_by_node[nodeCmpIdx]; i++) {
                    edge_t *edge2, *virtual_edge;
                    node_t *node_dest = edgedest_by_node[nodeCmpIdx][i];
                    HASH_FIND_STR(virtual_node->edges, node_dest->physical_id, virtual_edge);
                    assert(virtual_edge);
                    HASH_FIND_STR(node2->edges, virtual_edge->dest, edge2);
                    assert(edge2);
                    edge_merge_into(virtual_node, virtual_edge, node2, edge2, node_dest, nparts);
                    HASH_DEL(node2->edges, edge2);
                    if (!strncmp("virtual", node_dest->physical_id, 7)) {
                        /* Destroy previous virtual edge */
                        utarray_free(edge2->physical_link_idx);
                        utarray_free(edge2->subedges);
                        free(edge2->partitions);
                        free(edge2);
                    }
                }

                HASH_DEL(nodes, node2);
                switch_nodes[nodeCmpIdx] = NULL;
                HASH_ADD_STR(virtual_node->subnodes, physical_id, node2);

                    /* // TODO paths */

                    /* /\* Set edges *\/ */
                    /* netloc_edge_t *edge1, *edge_tmp1; */
                    /* netloc_node_iter_edges(node1, edge1, edge_tmp1) { */
                    /*     netloc_edge_t *virtual_edge = netloc_edge_construct(); */
                    /*     if (!first_virtual_edge) */
                    /*         first_virtual_edge = virtual_edge; */
                    /*     virtual_edge->node = virtual_node; */
                    /*     virtual_edge->dest = edge1->dest; */
                    /*     ret = edge_merge_into(virtual_edge, edge1, 0); */
                    /*     if (ret != NETLOC_SUCCESS) { */
                    /*         netloc_edge_destruct(virtual_edge); */
                    /*         goto ERROR; */
                    /*     } */
                    /*     HASH_ADD_PTR(virtual_node->edges, dest, virtual_edge); */

                    /*     /\* Change the reverse edge of the neighbours (reverse nodes) *\/ */
                    /*     netloc_node_t *reverse_node = edge1->dest; */
                    /*     netloc_edge_t *reverse_edge = edge1->other_way; */

                    /*     netloc_edge_t *reverse_virtual_edge = */
                    /*         netloc_edge_construct(); */
                    /*     reverse_virtual_edge->dest = virtual_node; */
                    /*     reverse_virtual_edge->node = reverse_node; */
                    /*     reverse_virtual_edge->other_way = virtual_edge; */
                    /*     virtual_edge->other_way = reverse_virtual_edge; */
                    /*     HASH_ADD_PTR(reverse_node->edges, dest, reverse_virtual_edge); */
                    /*     ret = edge_merge_into(reverse_virtual_edge, reverse_edge, 1); */
                    /*     if (ret != NETLOC_SUCCESS) { */
                    /*         goto ERROR; */
                    /*     } */
                    /*     HASH_DEL(reverse_node->edges, reverse_edge); */
                    /* } */

                    /* /\* We remove the node from the list of nodes *\/ */
                    /* HASH_DEL(topology->nodes, node1); */
                    /* HASH_ADD_STR(topology->nodes, physical_id, virtual_node); */
                    /* printf("First node found: %s (%s)\n", node1->description, node1->physical_id); */
            }
        }

        /* If virtual_node is not NULL, then there have been a virtual
           node added. We need to update the entries */
        if (NULL != virtual_node) {
            unsigned int num_edges = HASH_COUNT(virtual_node->edges);
            switch_nodes[nodeIdx] = virtual_node;
            num_edges_by_node[nodeIdx] = num_edges;
            edgedest_by_node[nodeIdx] = (node_t **)
                realloc(edgedest_by_node[nodeIdx], sizeof(node_t *[num_edges]));
            /* Reset edges destinations */
            edge_t *edge, *edge_tmp;
            int edge_idx = 0;
            HASH_SORT(virtual_node->edges, sort_by_dest);
            netloc_node_iter_edges(virtual_node, edge, edge_tmp) {
                HASH_FIND_STR(nodes, edge->dest, edgedest_by_node[nodeIdx][edge_idx]);
                assert(edgedest_by_node[nodeIdx][edge_idx]);
                edge_idx++;
            }
            for (int idx = nodeIdx + 1; idx < num_nodes; ++idx) {
                node = switch_nodes[idx];
                if (node /* SW node that has not yet been virtualized */
                    && /* linked to a virtualized node -> need to be updated */
                    (num_edges = HASH_COUNT(node->edges)) < num_edges_by_node[idx]) {
                    num_edges_by_node[idx] = num_edges;
                    edgedest_by_node[idx] = (node_t **)
                        realloc(edgedest_by_node[idx], sizeof(node_t *[num_edges]));
                    /* Reset edges destinations */
                    edge_idx = 0;
                    HASH_SORT(node->edges, sort_by_dest);
                    netloc_node_iter_edges(node, edge, edge_tmp) {
                        HASH_FIND_STR(nodes, edge->dest, edgedest_by_node[idx][edge_idx]);
                        assert(edgedest_by_node[idx][edge_idx]);
                        edge_idx++;
                    }
                }
            }
        }
    }

    ret = NETLOC_SUCCESS;
ERROR:
    for (int idx = 0; idx < num_nodes; idx++) {
        if (edgedest_by_node[idx])
            free(edgedest_by_node[idx]);
    }
    free(edgedest_by_node);
    free(num_edges_by_node);
    free(switch_nodes);
    return ret;
}

static inline void set_reverse_edges(node_t *nodes)
{
    node_t *node, *node_tmp, *dest_node;
    edge_t *edge, *edge_tmp;
    HASH_ITER(hh, nodes, node, node_tmp) {
        HASH_ITER(hh, node->edges, edge, edge_tmp) {
            if (edge->reverse_edge) {
                assert(!strncmp(edge->reverse_edge->dest, node->physical_id, MAX_STR));
                assert(edge->reverse_edge->reverse_edge == edge);
                continue;
            }
            HASH_FIND_STR(nodes, edge->dest, dest_node);
            assert(dest_node);
            HASH_FIND_STR(dest_node->edges, node->physical_id, edge->reverse_edge);
            assert(edge->reverse_edge);
            assert(!edge->reverse_edge->reverse_edge);
            edge->reverse_edge->reverse_edge = edge;
        }
    }
#ifdef NETLOC_DEBUG
    {
        /* Check every edge has its reverse_edge set */
        node_t *node, *node_tmp, *dest_node;
        edge_t *edge, *edge_tmp, *reverse_edge;
        unsigned int tutu = 0;
        HASH_ITER(hh, nodes, node, node_tmp) {
            HASH_ITER(hh, node->edges, edge, edge_tmp) {
                ++tutu;
                if(!edge->reverse_edge) {
                    HASH_FIND_STR(nodes, edge->dest, dest_node);
                    assert(dest_node);
                    HASH_FIND_STR(dest_node->edges, node->physical_id, reverse_edge);
                }
                assert(edge->reverse_edge);
            }
        }
    }
#endif /* NETLOC_DEBUG */
}

int netloc_write_into_xml_file(node_t *nodes, const UT_array *partitions,
                               const char *subnet, const char *path,
                               const char *hwlocpath,
                               const netloc_network_type_t transportType)
{
    int ret = NETLOC_ERROR;

    set_reverse_edges(nodes);
    find_similar_nodes(nodes, utarray_len(partitions));

    /* Create a netloc explicit_topology to ease the dump */
    netloc_network_explicit_t *topo;
    topo = create_netloc_network_explicit(subnet, hwlocpath,
                                          nodes, partitions);

    ret = netloc_write_xml_file(nodes, partitions, subnet, path,
                                hwlocpath, transportType);

    /* Free the network_explicit_t topo */
    netloc_network_explicit_destruct(topo);

    /* Untangle similar nodes so the virtualization is transparent */
    node_t *node, *node_tmp;
    HASH_ITER(hh, nodes, node, node_tmp) {
        if (node->subnodes) {
            /* Edges */
            edge_t *edge, *edge_tmp;
            HASH_ITER(hh, node->edges, edge, edge_tmp) {
                unsigned int i;
                node_t *src_node;
                /* Clean reverse edge if dest is not virtual */
                if (0 != strncmp("virtual", edge->dest, 7)) {
                    node_t *dest_node;
                    HASH_FIND_STR(nodes, edge->dest, dest_node);
                    assert(dest_node);
                    edge_t *reverse_edge = edge->reverse_edge;
                    assert(reverse_edge);
                    HASH_DEL(dest_node->edges, reverse_edge);
                    utarray_free(reverse_edge->physical_link_idx);
                    /* Unmerge revert subedges */
                    for (i = 0; i < utarray_len(reverse_edge->subedges); ++i) {
                        edge_t *sub = *(edge_t **)
                            utarray_eltptr(reverse_edge->subedges, i);
                        HASH_ADD_STR(dest_node->edges, dest, sub);
                    }
                    utarray_free(reverse_edge->subedges);
                    free(reverse_edge->partitions);
                    free(reverse_edge);
                }
                /* Clean edge */
                /* Unmerge subedges */
                for (i = 0; i < utarray_len(edge->subedges); ++i) {
                    edge_t *sub = *(edge_t **) utarray_eltptr(edge->subedges, i);
                    assert(sub->reverse_edge);
                    HASH_FIND_STR(node->subnodes, sub->reverse_edge->dest, src_node);
                    assert(src_node);
                    HASH_ADD_STR(src_node->edges, dest, sub);
                }
                utarray_free(edge->subedges);
                utarray_free(edge->physical_link_idx);
                free(edge->partitions);
                HASH_DEL(node->edges, edge);
                free(edge);
            }
            /* Nodes */
            node_t *subnode, *subnode_tmp;
            HASH_DEL(nodes, node);
            HASH_ITER(hh, node->subnodes, subnode, subnode_tmp) {
                HASH_DEL(node->subnodes, subnode);
                HASH_ADD_STR(nodes, physical_id, subnode);
            }
            /* Virtual Node */
            utarray_free(node->physical_links);
            free(node->partitions);
            free(node->description);
            free(node);
        }
    }
    return ret;
}
