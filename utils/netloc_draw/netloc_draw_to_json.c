/*
 * Copyright © 2016 Inria.  All rights reserved.
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

#include <jansson.h>

#include "netloc/dc.h"
#include "private/netloc.h"

#define JSON_DRAW_FILE_EDGE_ID "id"
#define JSON_DRAW_FILE_EDGE_SRC "src"
#define JSON_DRAW_FILE_EDGE_SRC_PORT "src_port"
#define JSON_DRAW_FILE_EDGE_DST "dst"
#define JSON_DRAW_FILE_EDGE_DST_PORT "dst_port"
#define JSON_DRAW_FILE_EDGE_GBITS "gbits"
#define JSON_DRAW_FILE_EDGE_TYPE "type"
#define JSON_DRAW_FILE_EDGE_PARTITIONS "part"
#define JSON_DRAW_FILE_NODE_ID "id"
#define JSON_DRAW_FILE_NODE_EDGES "edges"
#define JSON_DRAW_FILE_NODE_PARTITIONS "part"
#define JSON_DRAW_FILE_NODE_DESC "desc"
#define JSON_DRAW_FILE_NODE_HOSTNAME "hostname"
#define JSON_DRAW_FILE_NODE_HWLOCTOPO "topo"
#define JSON_DRAW_FILE_NODE_TYPE "type"
#define JSON_DRAW_FILE_GRAPH_TYPE "type"
#define JSON_DRAW_FILE_NODES "nodes"
#define JSON_DRAW_FILE_EDGES "edges"
#define JSON_DRAW_FILE_PARTITIONS "partitions"
#define JSON_DRAW_FILE_HWLOCTOPOS "hwloctopos"

static char *remove_quote(char *string)
{
    if (string[0] == '\'')
        return strndup(string+1, strlen(string)-2);
    else
        return strndup(string, strlen(string));
}

static int write_edge(json_t *json_edges, netloc_edge_t *edge)
{
    //netloc_node_t *src, *dest;
    char *src = edge->src_node_id;
    char *dest = edge->dest_node_id;

    json_t *json_edge = json_object();
    json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_ID, json_integer(edge->edge_uid));
    json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_SRC, json_string(src));
    json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_SRC_PORT, json_string(edge->src_port_id));
    json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_DST, json_string(dest));
    json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_DST_PORT, json_string(edge->dest_port_id));
    json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_GBITS, json_real(edge->gbits));

    if (edge->src_node->node_type == NETLOC_NODE_TYPE_HOST
            || edge->dest_node->node_type == NETLOC_NODE_TYPE_HOST)
        json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_TYPE, json_string("SH"));
    else
        json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_TYPE, json_string("SS"));

    json_t *json_partitions = json_array();
    for (int p = 0; p < edge->num_partitions; p++)
    {
        int partition = edge->partitions[p];
        json_array_append_new(json_partitions, json_integer(partition));
    }
    json_object_set_new(json_edge, JSON_DRAW_FILE_EDGE_PARTITIONS, json_partitions);

    json_array_append_new(json_edges, json_edge);

    return 0;
}

static int write_node(json_t *json_nodes, netloc_node_t *node)
{
    //unsigned long uid = node->physical_id_int;
    //char *node_label = node->physical_id;
    char *id = node->physical_id;
    char *desc = remove_quote(node->description);
    char *hostname = node->hostname;
    int topoIdx = node->topoIdx;

    json_t *json_node = json_object();
    json_object_set_new(json_node, JSON_DRAW_FILE_NODE_ID, json_string(id));
    json_object_set_new(json_node, JSON_DRAW_FILE_NODE_DESC, json_string(desc));
    json_object_set_new(json_node, JSON_DRAW_FILE_NODE_HOSTNAME, json_string(hostname));
    json_object_set_new(json_node, JSON_DRAW_FILE_NODE_HWLOCTOPO, json_integer(topoIdx));

    free(desc);

    json_t *json_edges = json_array();
    for (int n = 0; n < node->num_edges; n++)
    {
        netloc_edge_t *edge = node->edges[n];
        json_array_append_new(json_edges, json_integer(edge->edge_uid));
    }
    json_object_set_new(json_node, JSON_DRAW_FILE_NODE_EDGES, json_edges);

    json_t *json_partitions = json_array();
    for (int p = 0; p < node->num_partitions; p++)
    {
        int partition = node->partitions[p];
        json_array_append_new(json_partitions, json_integer(partition));
    }
    json_object_set_new(json_node, JSON_DRAW_FILE_NODE_PARTITIONS, json_partitions);

    if (node->node_type == NETLOC_NODE_TYPE_HOST) {
        json_object_set_new(json_node, JSON_DRAW_FILE_NODE_TYPE, json_string("host"));
    }
    else if (node->node_type == NETLOC_NODE_TYPE_SWITCH) {
        json_object_set_new(json_node, JSON_DRAW_FILE_NODE_TYPE, json_string("switch"));
    }

    json_array_append_new(json_nodes, json_node);

    return 0;
}

static int handle_node(netloc_node_t *node, json_t *json_nodes)
{
    write_node(json_nodes, node);
    return 0; // TODO
}

static int handle_edge(netloc_edge_t *edge, json_t *json_edges)
{
    write_edge(json_edges, edge);
    return 0; // TODO
}

static int handle_partitions(netloc_topology_t topology, json_t *json_partitions)
{
    for (int p = 0; p < topology->num_partitions; p++)
    {
        json_array_append_new(json_partitions, json_string(topology->partitions[p]));
    }
    return 0; // TODO
}

static int handle_topos(netloc_topology_t topology, json_t *json_topos)
{
    for (int p = 0; p < topology->num_topos; p++)
    {
        json_array_append_new(json_topos, json_string(topology->topos[p]));
    }
    return 0; // TODO
}

static int json_write(netloc_topology_t topology, FILE *output)
{
    netloc_dt_lookup_table_iterator_t hti;

    json_t *json_nodes = json_array();
    json_t *json_edges = json_array();
    json_t *json_partitions = json_array();
    json_t *json_topos = json_array();

    netloc_node_t *node;
    netloc_dt_lookup_table_t nodes;
    netloc_get_all_nodes(topology, &nodes);

    hti = netloc_dt_lookup_table_iterator_t_construct(nodes);
    while ((node =
            (netloc_node_t *)netloc_lookup_table_iterator_next_entry(hti))) {
        handle_node(node, json_nodes);
    }

    netloc_dt_lookup_table_t edges = topology->edges;
    hti = netloc_dt_lookup_table_iterator_t_construct(edges);

    netloc_edge_t *edge;

    while ((edge =
                (netloc_edge_t *)netloc_lookup_table_iterator_next_entry(hti))) {
        handle_edge(edge, json_edges);
    }

    handle_partitions(topology, json_partitions);
    handle_topos(topology, json_topos);

    json_t *json_root = json_object();
    json_object_set_new(json_root, JSON_DRAW_FILE_GRAPH_TYPE, json_string("tree"));
    json_object_set_new(json_root, JSON_DRAW_FILE_NODES, json_nodes);
    json_object_set_new(json_root, JSON_DRAW_FILE_EDGES, json_edges);
    json_object_set_new(json_root, JSON_DRAW_FILE_PARTITIONS, json_partitions);
    json_object_set_new(json_root, JSON_DRAW_FILE_HWLOCTOPOS, json_topos);

    char *json = json_dumps(json_root, 0);
    //FILE *output = fopen("/tmp/test.json", "w+");
    fprintf(output, "%s", json);
    //json_dump_file(json_root, "/tmp/test.json", 0);

    /* Free json objects */
    json_decref(json_root);

    return 0; // TODO
}

int netloc_to_json_draw(netloc_topology_t topology, int simplify)
{
    static FILE *output;
    char *node_uri = topology->network->node_uri;
    int basename_len = strlen(node_uri)-10;
    char *basename = (char *)malloc((basename_len+1)*sizeof(char));
    char *draw;

    netloc_topology_set_all_partitions(topology);

    netloc_read_hwloc(topology);

    if (simplify)
        netloc_topology_simplify(topology);

    strncpy(basename, node_uri, basename_len);
    basename[basename_len] = '\0';

    asprintf(&draw, "%s%s%s.json", basename, "draw", simplify ? "-simple": "");
    output = fopen(draw, "w");

    json_write(topology, output);
            
    fclose(output);
    return 0; // TODO
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

int main(int argc, char **argv)
{
    int ret;

    if (argc < 2 || argc > 3) {
        goto wrong_params;
    }

    int cargc = argc;
    char **cargv = argv;
    char *netloc_dir;
    char *param;
    int simplify = 0;

    read_param(&cargc, &cargv);
    char *path = read_param(&cargc, &cargv);
    asprintf(&netloc_dir, "file://%s/%s", path, "netloc");

    if ((param = read_param(&cargc, &cargv))) {
        simplify = atoi(param);
    }

    netloc_network_t *network = NULL;
    netloc_topology_t topology;

    // Find a specific InfiniBand network
    network = netloc_dt_network_t_construct();
    network->network_type = NETLOC_NETWORK_TYPE_INFINIBAND;

    // Search for the specific network
    ret = netloc_find_network(netloc_dir, network);
    if( NETLOC_SUCCESS != ret ) {
        fprintf(stderr, "Error: network not found!\n");
        netloc_dt_network_t_destruct(network);
        return NETLOC_ERROR;
    }
    printf("Found Network: %s\n", netloc_pretty_print_network_t(network));

    // Attach to the network
    ret = netloc_attach(&topology, *network);
    if( NETLOC_SUCCESS != ret ) {
        fprintf(stderr, "Error: netloc_attach returned an error (%d)\n", ret);
        return ret;
    }

    netloc_to_json_draw(topology, simplify);

    return 0;

wrong_params:
    printf("Usage: %s <netloc_dir> [simplify (1 or 0)]\n", argv[0]);
    return -1;
}

