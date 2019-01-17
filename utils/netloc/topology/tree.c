#include <netloc.h>
#include "tree.h"

typedef struct netloc_analysis_data_t {
    int level;
    void *userdata;
} netloc_analysis_data;


/* Complete the topology to have a complete balanced tree  */
void netloc_arch_tree_complete(netloc_topology_t *topology, UT_array **down_degrees_by_level,
        int num_hosts, int **parch_idx)
{
    int num_levels = topology->ndims;
    NETLOC_int *max_degrees = topology->dimensions;

    /* Complete the tree by inserting nodes */
    for (int l = 0; l < num_levels-1; l++) { // from the root to the leaves
        int num_degrees = utarray_len(down_degrees_by_level[l]);
        int *degrees = (int *)down_degrees_by_level[l]->d;
        NETLOC_int max_degree = max_degrees[l];

        unsigned int down_level_idx = 0;
        UT_array *down_level_degrees = down_degrees_by_level[l+1];
        NETLOC_int down_level_max_degree = max_degrees[l+1];
        for (int d = 0; d < num_degrees; d++) {
            int degree = degrees[d];
            if (degree > 0) {
                down_level_idx += degree;
                if (degree < max_degree) {
                    int missing_degree = (degree-max_degree)*down_level_max_degree;
                    utarray_insert(down_level_degrees, &missing_degree, down_level_idx);
                    down_level_idx++;
                }
            } else {
                int missing_degree = degree*down_level_max_degree;
                utarray_insert(down_level_degrees, &missing_degree, down_level_idx);
                down_level_idx++;
            }
        }
    }

    /* Indices for the list of hosts, in the complete architecture */
    int num_degrees = utarray_len(down_degrees_by_level[num_levels-1]);
    int *degrees = (int *)down_degrees_by_level[num_levels-1]->d;
    NETLOC_int max_degree = max_degrees[num_levels-1];
    int ghost_idx = 0;
    int idx = 0;
    int *arch_idx = (int *)malloc(sizeof(int[num_hosts]));
    for (int d = 0; d < num_degrees; d++) {
        int degree = degrees[d];
        int diff;

        if (degree > 0) {
            diff = max_degree-degree;
        } else {
            diff = -degree;
        }

        for (int i = 0; i < degree; i++) {
            arch_idx[idx++] = ghost_idx++;
        }
        ghost_idx += diff;
    }
    *parch_idx = arch_idx;
}


int partition_topology_to_tleaf(netloc_machine_t *machine)
{
    int ret = 0;
    netloc_node_t *node, *node_tmp;
    netloc_edge_t *edge, *edge_tmp;
    /* For each partition, we try to match a tree */
    for (int p = 0; p < machine->npartitions; p++) {
        netloc_topology_t *topology = (netloc_topology_t *)
            malloc(sizeof(netloc_topology_t));
        topology->type = NETLOC_ARCH_TREE;
        topology->subtopo = NULL;
        machine->partitions[p].topology = topology;

        UT_array *nodes;
        utarray_new(nodes, &ut_ptr_icd);

        /* we build nodes from host list in the given partition
         * and we init all the analysis data */
        void *userdata;
        netloc_analysis_data *analysis_data;
        netloc_machine_iter_nodes(machine, node, node_tmp) {
            userdata = node->userdata;
            node->userdata = (void *)malloc(sizeof(netloc_analysis_data));
            analysis_data = (netloc_analysis_data *)node->userdata;
            analysis_data->level = -1;
            analysis_data->userdata = userdata;

            netloc_node_iter_edges(node, edge, edge_tmp) {
                userdata = edge->userdata;
                edge->userdata = (void *)malloc(sizeof(netloc_analysis_data));
                analysis_data = (netloc_analysis_data *)edge->userdata;
                analysis_data->level = -1;
                analysis_data->userdata = userdata;
            }

            if (find_partition_number(node->nparts, node->newpartitions, p) != -1 &&
                    netloc_node_is_host(node)) {
                utarray_push_back(nodes, &node);
            }
        }

        /* We set the levels in the analysis data */
        /* Upward edges will have the level of the source node and downward edges
         * will have -1 as level */
        /* We start with nodes being the list of hosts */
        int num_levels = 0;
        netloc_node_t *current_node = /* pointer to one host node */
            *(void **)utarray_eltptr(nodes, 0);
        while (utarray_len(nodes)) {
            UT_array *new_nodes;
            utarray_new(new_nodes, &ut_ptr_icd);

            for (unsigned int n = 0; n < utarray_len(nodes); n++) {
                netloc_node_t *node = *(void **)utarray_eltptr(nodes, n);
                netloc_analysis_data *node_data = (netloc_analysis_data *)node->userdata;
                /* There is a problem, this is not a tree */
                if (node_data->level != -1 && node_data->level != num_levels) {
                    utarray_free(new_nodes);
                    ret = -1;
                    goto end;
                }
                else {
                    node_data->level = num_levels;
                    netloc_node_iter_edges(node, edge, edge_tmp) {
                        if (find_partition_number(edge->nparts, edge->newpartitions, p) == -1)
                            continue;
                        netloc_analysis_data *edge_data = (netloc_analysis_data *)edge->userdata;

                        netloc_node_t *dest = edge->dest;
                        /* If node is not in the partition */
                        if (find_partition_number(node->nparts, node->newpartitions, p) == -1)
                            continue;
                        netloc_analysis_data *dest_data = (netloc_analysis_data *)dest->userdata;
                        /* If we are going back */
                        if (dest_data->level != -1 && dest_data->level < num_levels) {
                            continue;
                        }
                        else {
                            if (dest_data->level != num_levels) {
                                edge_data->level = num_levels;
                                utarray_push_back(new_nodes, &dest);
                            }
                        }
                    }
                }
            }
            num_levels++;
            utarray_free(nodes);
            nodes = new_nodes;
        }

        /* We go though the tree to order the leaves and find the tree
         * structure */
        UT_array *ordered_name_array = NULL;
        UT_array **down_degrees_by_level = NULL;
        NETLOC_int *max_down_degrees_by_level;

        utarray_new(ordered_name_array, &ut_ptr_icd);

        /* init array of utarrays */
        down_degrees_by_level = (UT_array **)malloc(num_levels*sizeof(UT_array *));
        for (int l = 0; l < num_levels; l++) {
            utarray_new(down_degrees_by_level[l], &ut_int_icd);
        }
        /* init value for max_down_degree is 0 */
        max_down_degrees_by_level = (NETLOC_int *)
            calloc(num_levels-1, sizeof(NETLOC_int));

        UT_array *down_edges = NULL;
        utarray_new(down_edges, &ut_ptr_icd);
        netloc_edge_t *up_edge = current_node->edges;
        utarray_push_back(ordered_name_array, &current_node);
        while (1) { /* while there are edges to follow */
            if (utarray_len(down_edges)) { /* if we still have down_edges */
                netloc_edge_t *down_edge = *(void **)utarray_back(down_edges);
                utarray_pop_back(down_edges);
                netloc_node_t *dest_node = down_edge->dest;
                if (netloc_node_is_host(dest_node)) {
                    utarray_push_back(ordered_name_array, &dest_node);
                }
                else {
                    netloc_edge_t *edge, *edge_tmp;
                    int num_edges = 0;
                    netloc_node_iter_edges(dest_node, edge, edge_tmp) {
                        if (find_partition_number(edge->nparts, edge->newpartitions, p) == -1)
                            continue;
                        netloc_analysis_data *edge_data = (netloc_analysis_data *)edge->userdata;
                        int edge_level = edge_data->level;
                        if (edge_level == -1) {
                            utarray_push_back(down_edges, &edge);
                            num_edges++;
                        }
                    }
                    int level = ((netloc_analysis_data *)dest_node->userdata)->level;
                    utarray_push_back(down_degrees_by_level[num_levels-1-level], &num_edges);
                    max_down_degrees_by_level[num_levels-1-level] =
                        max_down_degrees_by_level[num_levels-1-level] > num_edges ?
                        max_down_degrees_by_level[num_levels-1-level]: num_edges;
                }
            }
            else { /* all met down edges have been processed */
                netloc_edge_t *new_up_edge = NULL;
                if (!up_edge)
                    break;
                if (find_partition_number(up_edge->nparts, up_edge->newpartitions, p) == -1)
                    break;

                netloc_node_t *up_node = up_edge->dest;
                netloc_edge_t *edge, *edge_tmp;
                int num_edges = 0;
                /* We go through edges of the up node to put them in up_edge or down_edges */
                netloc_node_iter_edges(up_node, edge, edge_tmp) {
                    if (find_partition_number(edge->nparts, edge->newpartitions, p) == -1)
                        continue;
                    netloc_analysis_data *edge_data = (netloc_analysis_data *)edge->userdata;
                    int edge_level = edge_data->level;

                    netloc_node_t *dest_node = edge->dest;

                    /* If the is the node where we are from */
                    if (dest_node == up_edge->node) {
                        num_edges++;
                        continue;
                    }

                    /* Downward edge */
                    if (edge_level == -1) {
                        utarray_push_back(down_edges, &edge);
                        num_edges++;
                    }
                    /* Upward edge */
                    else {
                        new_up_edge = edge;
                    }

                }
                int level = ((netloc_analysis_data *)up_node->userdata)->level;
                utarray_push_back(down_degrees_by_level[num_levels-1-level], &num_edges);
                max_down_degrees_by_level[num_levels-1-level] =
                    max_down_degrees_by_level[num_levels-1-level] > num_edges ?
                    max_down_degrees_by_level[num_levels-1-level]: num_edges;
                up_edge = new_up_edge;
            }
        }

        topology->ndims = num_levels-1;
        topology->dimensions = max_down_degrees_by_level;

        int network_coeff = 2;
        topology->costs = (NETLOC_int *)malloc(sizeof(NETLOC_int[topology->ndims]));

        int *arch_idx;
        int num_nodes = utarray_len(ordered_name_array);

        if (num_nodes == 1) { /* if partition is a singleton */
            arch_idx = (int *)malloc(sizeof(int));
            arch_idx[0] = 0;

        } else {
            topology->costs[topology->ndims-1] = 1;
            for (int i = topology->ndims-2; i >= 0 ; i--) {
                topology->costs[i] = topology->costs[i+1]*network_coeff;
            }
            /* Now we have the degree of each node, so we can complete the topology to
             * have a complete balanced tree as requested by the tleaf structure */
            netloc_arch_tree_complete(topology, down_degrees_by_level, num_nodes, &arch_idx);
        }

        netloc_node_t **ordered_nodes = (netloc_node_t **)ordered_name_array->d;
        for (int i = 0; i < num_nodes; i++) {
            netloc_node_t *node = ordered_nodes[i];
            if (NULL == node->newtopo_positions) {
                node->newtopo_positions =
                    (netloc_position_t *)calloc(node->nparts,
                            sizeof(netloc_position_t));
            }
            // TODO results from previous find_partition_number can be saved */
            int local_p = find_partition_number(node->nparts, node->newpartitions, p);
            node->newtopo_positions[local_p].idx = arch_idx[i];
            node->newtopo_positions[local_p].coords = (int *)
                malloc(sizeof(int *[topology->ndims]));
            idx_to_coords(arch_idx[i], topology->ndims,
                    topology->dimensions, node->newtopo_positions[local_p].coords);
        }
        free(arch_idx);

        machine->partitions[p].num_hosts = num_nodes;

end:
        if (nodes)
            utarray_free(nodes);

        if (ordered_name_array)
            utarray_free(ordered_name_array);

        if (down_degrees_by_level) {
            for (int l = 0; l < num_levels; l++) {
                utarray_free(down_degrees_by_level[l]);
            }
            free(down_degrees_by_level);
        }

        if (down_edges)
            utarray_free(down_edges);

        /* We copy back all userdata */
        netloc_machine_iter_nodes(machine, node, node_tmp) {
            netloc_analysis_data *analysis_data =
                (netloc_analysis_data *)node->userdata;
            if (find_partition_number(node->nparts, node->newpartitions,
                        p) != -1 && analysis_data->level == -1) {
                ret = -1;
                printf("The node %s was not browsed\n", node->description);
            }
            free(analysis_data);

            netloc_node_iter_edges(node, edge, edge_tmp) {
                netloc_analysis_data *analysis_data =
                    (netloc_analysis_data *)edge->userdata;
                node->userdata = analysis_data->userdata;
                free(analysis_data);
            }
        }
    }

    return ret;
}



