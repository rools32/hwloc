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

#include <sys/types.h>
#include <dirent.h>

#include <private/netloc.h>
#include <netloc.h>
#include <hwloc.h>

static UT_icd topos_icd = {sizeof(hwloc_topology_t), NULL, NULL, NULL};

int netloc_network_explicit_read_hwloc(netloc_network_explicit_t *topology,
                                       int num_nodes, netloc_node_t **node_list)
{
    int ret = NETLOC_ERROR, all = 0, num_topos = 0, n = 0;

    if (!topology->hwlocpaths) {
        fprintf(stderr, "WARN: No hwloc files recorded in the topology\n");
        goto ERROR;
    }

    if (!topology->hwloc_topos &&
        !(topology->hwloc_topos = calloc(topology->nb_hwloc_topos, sizeof(hwloc_topology_t)))) {
        fprintf(stderr, "ERROR: list of hwloc topologies cannot be allocated\n");
        goto ERROR;
    }

    if (!num_nodes) {
        netloc_node_t *pnode, *ptmp;
        num_nodes = HASH_COUNT(topology->nodes);
        node_list = malloc(sizeof(netloc_node_t *[num_nodes]));
        if (!node_list) {
            fprintf(stderr, "ERROR: node_list cannot be allocated\n");
            goto ERROR;
        }
        netloc_network_explicit_iter_nodes(topology, pnode, ptmp) {
            node_list[n++] = pnode;
        }
        all = 1;
    }

    /* Load all hwloc topologies */
    size_t node_id;
    for (int n = 0; n < num_nodes; ++n) {
        node_id = node_list[n]->hwloc_topo_idx;
        if (!topology->hwloc_topos[node_id]) {
            hwloc_topology_init(&topology->hwloc_topos[node_id]);
            hwloc_topology_set_flags(topology->hwloc_topos[node_id],
                                     HWLOC_TOPOLOGY_FLAG_WHOLE_SYSTEM);

            ret = hwloc_topology_set_xml(topology->hwloc_topos[node_id],
                                         topology->hwlocpaths[node_id]);
            if (ret == -1) {
                fprintf(stderr, "WARN: no topology for %s\n",
                        topology->hwlocpaths[node_id]);
                hwloc_topology_destroy(topology->hwloc_topos[node_id]);
                topology->hwloc_topos[node_id] = NULL;
                continue;
            }

            ret = hwloc_topology_set_all_types_filter(topology->hwloc_topos[node_id],
                                                      HWLOC_TYPE_FILTER_KEEP_STRUCTURE);
            if (ret == -1) {
                fprintf(stderr, "hwloc_topology_set_all_types_filter failed\n");
                goto ERROR;
            }

            ret = hwloc_topology_set_io_types_filter(topology->hwloc_topos[node_id],
                                                     HWLOC_TYPE_FILTER_KEEP_NONE);
            if (ret == -1) {
                fprintf(stderr, "hwloc_topology_set_all_types_filter failed\n");
                goto ERROR;
            }

            ret = hwloc_topology_load(topology->hwloc_topos[node_id]);
            if (ret == -1) {
                fprintf(stderr, "hwloc_topology_load failed\n");
                goto ERROR;
            }

            ++num_topos;
        }
    }

    printf("%d hwloc topolog%s found:\n", num_topos, num_topos > 1 ? "ies":"y");
    for (unsigned int p = 0; p < topology->nb_hwloc_topos; p++) {
        if (topology->hwloc_topos[p])
            printf("\t'%s'\n", topology->hwlocpaths[p]);
    }

    ret = NETLOC_SUCCESS;

ERROR:
    if (all) {
        free(node_list);
    }

    return ret;
}

/* Set the info from hwloc of the node in the correspondig arch */
int netloc_arch_node_get_hwloc_info(netloc_arch_node_t *arch_node,
                                    netloc_network_explicit_t *nettopology)
{
    hwloc_topology_t topology;
    topology = nettopology->hwloc_topos[arch_node->node->hwloc_topo_idx];

    hwloc_obj_t root = hwloc_get_root_obj(topology);

    int depth = hwloc_topology_get_depth(topology);
    hwloc_obj_t first_object = root->first_child;

    UT_array **down_degrees_by_level;
    NETLOC_int *max_down_degrees_by_level;

    down_degrees_by_level = (UT_array **)malloc(depth*sizeof(UT_array *));
    for (int l = 0; l < depth; l++) {
        utarray_new(down_degrees_by_level[l], &ut_int_icd);
    }
    max_down_degrees_by_level = (NETLOC_int *)
        calloc(depth-1, sizeof(NETLOC_int));

    int level = depth-1;
    hwloc_obj_t current_object = first_object;
    while (level >= 1) {
        int degree = 1;
        /* we go through the siblings */
        while (current_object->next_sibling) {
            current_object = current_object->next_sibling;
            degree++;
        }
        /* Add the degree to the list of degrees */
        utarray_push_back(down_degrees_by_level[depth-1-level], &degree);
        max_down_degrees_by_level[depth-1-level] =
            max_down_degrees_by_level[depth-1-level] > degree ?
            max_down_degrees_by_level[depth-1-level] : degree;

        current_object = current_object->next_cousin;

        if (!current_object) {
            level--;
            if (!first_object->first_child)
                break;
            first_object = first_object->first_child;
            current_object = first_object;
        }
    }

    /* List of PUs */
    unsigned int max_os_index = 0;
    UT_array *ordered_host_array;
    int *ordered_hosts;
    utarray_new(ordered_host_array, &ut_int_icd);
    current_object = first_object;
    while (current_object) {
        max_os_index = (max_os_index >= current_object->os_index)?
            max_os_index: current_object->os_index;
        utarray_push_back(ordered_host_array, &current_object->os_index);
        current_object = current_object->next_cousin;
    }
    ordered_hosts = (int *)ordered_host_array->d;;

    /* Weight for the edges in the tree */
    NETLOC_int *cost = (NETLOC_int *)malloc((depth-1)*sizeof(NETLOC_int));
    int level_coeff = 3;
    cost[depth-2] = 1;
    for (int l = depth-3; l >= 0; l--) {
        cost[l] = cost[l+1]*level_coeff;
    }

    netloc_arch_tree_t *tree = (netloc_arch_tree_t *)
        malloc(sizeof(netloc_arch_tree_t));
    tree->num_levels = depth-1;
    tree->degrees = max_down_degrees_by_level;
    tree->costs = cost;

    int *arch_idx;
    int num_cores = utarray_len(ordered_host_array);
    netloc_arch_tree_complete(tree, down_degrees_by_level, num_cores, &arch_idx);

    int *slot_idx = (int *)malloc(sizeof(int[max_os_index+1]));
    for (int i = 0; i < num_cores; i++) {
        slot_idx[ordered_hosts[i]] = arch_idx[i];
    }

    int num_leaves = netloc_arch_tree_num_leaves(tree);
    int *slot_os_idx = (int *)malloc(sizeof(int[num_leaves]));
    for (int i = 0; i < num_cores; i++) {
        slot_os_idx[arch_idx[i]] = ordered_hosts[i];
    }
    free(arch_idx);

    arch_node->slot_tree = tree;
    arch_node->slot_idx = slot_idx;
    arch_node->slot_os_idx = slot_os_idx;
    arch_node->num_slots = max_os_index+1;

    for (int l = 0; l < depth; l++) {
        utarray_free(down_degrees_by_level[l]);
    }
    free(down_degrees_by_level);

    utarray_free(ordered_host_array);

    return NETLOC_SUCCESS;
}
