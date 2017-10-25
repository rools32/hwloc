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
 * This file provides general function to generate XML topology files.
 */

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <netloc.h>
#include <private/netloc.h>
#include <private/autogen/config.h>
#include <private/utils/netloc.h>
#include <private/utils/xml.h>

#include <netloc/uthash.h>
#include <netloc/utarray.h>

#include <dirent.h>
#include <libgen.h>

static int
node_belongs_to_a_partition(const node_t *node, const unsigned int nparts) {
    for(unsigned int p = 0; node->partitions && p < nparts; ++p)
        if (node->partitions[p]) return 1;
    return 0;
}

static int
edge_belongs_to_a_partition(const edge_t *edge, const unsigned int nparts) {
    for(unsigned int p = 0; edge->partitions && p < nparts; ++p)
        if (edge->partitions[p]) return 1;
    return 0;
}

static inline void insert_xml_link(xml_node_ptr links_node,
                                   physical_link_t *link)
{
    xml_char *buff = NULL;
    char *strBuff = NULL;
    int strBuffSize = 0;
    xml_node_ptr crt_node;
    /* Add current connexion description */
    buff = xml_char_strdup(link->description);
    crt_node = xml_node_child_new(links_node, NULL, BAD_CAST "link", buff);
    xml_char_free(buff); buff = NULL;
    /* Set srcport */
    strBuffSize = asprintf(&strBuff, "%d", link->ports[0]);
    if (0 < strBuffSize) {
        xml_node_attr_cpy_add(crt_node, BAD_CAST "srcport", strBuff);
        free(strBuff);
    }
    strBuff = NULL;
    /* Set destport */
    strBuffSize = asprintf(&strBuff, "%d", link->ports[1]);
    if (0 < strBuffSize) {
        xml_node_attr_cpy_add(crt_node, BAD_CAST "destport", strBuff);
        free(strBuff);
    }
    strBuff = NULL;
    /* Set speed */
    xml_node_attr_cpy_add(crt_node, BAD_CAST "speed", link->speed);
    /* Set width */
    xml_node_attr_cpy_add(crt_node, BAD_CAST "width", link->width);
    /* Set bandwidth */
    strBuffSize = asprintf(&strBuff, "%f", link->gbits);
    if (0 < strBuffSize) {
        xml_node_attr_cpy_add(crt_node, BAD_CAST "bandwidth", strBuff);
        free(strBuff);
    }
    strBuff = NULL;
    /* Set logical_id */
    strBuffSize = asprintf(&strBuff, "%llu", link->int_id);
    if (0 < strBuffSize) {
        xml_node_attr_cpy_add(crt_node, BAD_CAST "logical_id", strBuff);
        free(strBuff);
    }
    strBuff = NULL;
    /* Set reverse physical_link->logical_id */
    if (link->other_link
        && 0 < asprintf(&strBuff, "%llu", link->other_link->int_id)) {
        xml_node_attr_cpy_add(crt_node, BAD_CAST "reverse_logical_id", strBuff);
        free(strBuff);
    }
    strBuff = NULL;
}

static inline void insert_xml_edge(xml_node_ptr con_node, edge_t *edge,
                                   node_t *node)
{
    xml_char *buff = NULL;
    char *strBuff = NULL;
    int strBuffSize = 0;
    xml_node_ptr links_node;
    /* Set bandwidth */
    strBuffSize = asprintf(&strBuff, "%f", edge->total_gbits);
    if (0 < strBuffSize) {
        xml_node_attr_cpy_add(con_node, BAD_CAST "bandwidth", strBuff);
        free(strBuff);
    }
    strBuff = NULL;
    /* Set nblinks */
    unsigned int num_links = utarray_len(edge->physical_link_idx);
    strBuffSize = asprintf(&strBuff, "%u", num_links);
    if (0 < strBuffSize) {
        xml_node_attr_cpy_add(con_node, BAD_CAST "nblinks", strBuff);
        free(strBuff);
    }
    strBuff = NULL;
    /* Add src */
    buff = xml_char_strdup(node->physical_id);
    assert(buff);
    xml_node_child_new(con_node, NULL, BAD_CAST "src", buff);
    xml_char_free(buff); buff = NULL;
    /* Add dest */
    buff = xml_char_strdup(edge->dest);
    assert(buff);
    xml_node_child_new(con_node, NULL, BAD_CAST "dest", buff);
    xml_char_free(buff); buff = NULL;
    if (edge_is_virtual(edge)) {
        xml_node_ptr subcons_node, subcon_node;
        /* Set virtual="yes" */
        xml_node_attr_add(con_node, BAD_CAST "virtual", BAD_CAST "yes");
        subcons_node = xml_node_child_new(con_node, NULL,
                                          BAD_CAST "subconnexions", NULL);
        /* Set size */
        unsigned int num_subedges = utarray_len(edge->subedges);
        strBuffSize = asprintf(&strBuff, "%u", num_subedges);
        if (0 < strBuffSize) {
            xml_node_attr_cpy_add(subcons_node, BAD_CAST "size", strBuff);
            free(strBuff);
        }
        strBuff = NULL;
        /* Insert subedges */
        node_t *real_node = NULL;
        for (unsigned int se = 0; se < num_subedges; ++se) {
            edge_t *subedge = *(edge_t **)utarray_eltptr(edge->subedges, se);
            if (node_is_virtual(node))
                HASH_FIND_STR(node->subnodes, subedge->reverse_edge->dest,
                              real_node);
            else
                HASH_FIND_STR(nodes, subedge->reverse_edge->dest, real_node);
            assert(real_node);
            subcon_node = xml_node_child_new(subcons_node, NULL,
                                             BAD_CAST "connexion", NULL);
            insert_xml_edge(subcon_node, subedge, real_node);
        }
    } else {
        /* Add links */
        links_node = xml_node_child_new(con_node, NULL, BAD_CAST "links", NULL);
        for (unsigned int l = 0; l < num_links; l++) {
            unsigned int link_idx = *(unsigned int *)
                utarray_eltptr(edge->physical_link_idx, l);
            physical_link_t *link = (physical_link_t *)
                utarray_eltptr(node->physical_links, link_idx);
            insert_xml_link(links_node, link);
        }
    }
}

static inline void insert_xml_node(xml_node_ptr crt_node, node_t *node,
                                   char *hwloc_path)
{
    xml_char *buff = NULL;
    char *strBuff = NULL;
    int strBuffSize = 0;
    /* Set mac_addr */
    if (node->physical_id && 0 < strlen(node->physical_id)) {
        xml_node_attr_cpy_add(crt_node, BAD_CAST "mac_addr", node->physical_id);
    }
    /* Set type */
    xml_node_attr_cpy_add(crt_node, BAD_CAST "type",
                          netloc_node_type_encode(node->type));
    if (node->hostname && 0 < strlen(node->hostname)) {
        /* Set name */
        xml_node_attr_cpy_add(crt_node, BAD_CAST "name", node->hostname);
        /* Set hwloc_path iif node is a host */
        if (NETLOC_NODE_TYPE_HOST == node->type && hwloc_path) {
            FILE *fxml;
            strBuffSize = asprintf(&strBuff, "%s/%s.diff.xml",
                                   hwloc_path, node->hostname);
            if (0 > strBuffSize)
                strBuff = NULL;
            if (!(fxml = fopen(strBuff, "r"))) {
                strBuffSize -= 8;
                strcpy(&strBuff[strBuffSize], "xml");
                if (!(fxml = fopen(strBuff, "r"))) {
                    fprintf(stderr, "Hwloc file absent: %s\n", strBuff);
                    strBuffSize = 0;
                } else
                    fclose(fxml);
            } else
                fclose(fxml);
            if (0 < strBuffSize) {
                xml_node_attr_cpy_add(crt_node, BAD_CAST "hwloc_file",
                                      1+strrchr(strBuff, '/'));
            }
            free(strBuff); strBuff = NULL;
        }
    } else if (NETLOC_NODE_TYPE_HOST == node->type) {
        fprintf(stderr, "WARN: Host node with address %s has no hostname\n",
                node->physical_id);
    }
    /* Add description */
    if (node->description && 0 < strlen(node->description)) {
        buff = xml_char_strdup(node->description);
        if(buff) {
            xml_node_child_new(crt_node, NULL, BAD_CAST "description", buff);
        }
        xml_char_free(buff);
    }
}

static inline int insert_extra(xml_node_ptr network_node, char *full_hwloc_path,
                               const unsigned int len_partitions)
{
    char *strBuff;
    unsigned int part_size = 0, strBuffSize;
    xml_node_ptr part_node = NULL, crt_node = NULL, nodes_node = NULL,
        cons_node = NULL, explicit_node = NULL;
    part_node = xml_node_new(NULL, BAD_CAST "partition");
    explicit_node = xml_node_child_new(part_node, NULL,
                                       BAD_CAST "explicit", NULL);
    nodes_node = xml_node_child_new(explicit_node, NULL,
                                    BAD_CAST "nodes", NULL);
    cons_node = xml_node_child_new(explicit_node, NULL,
                                   BAD_CAST "connexions",NULL);
    /* Set name */
    xml_node_attr_add(part_node, BAD_CAST "name",
                      BAD_CAST "/extra+structural/");
    /* Add nodes */
    node_t *node, *node_tmp;
    HASH_ITER(hh, nodes, node, node_tmp) {
        /* Check if node belongs to no partition */
        if (!node_belongs_to_a_partition(node, len_partitions)) {
            ++part_size;
            crt_node = xml_node_child_new(nodes_node, NULL,
                                          BAD_CAST "node", NULL);
            insert_xml_node(crt_node, node, full_hwloc_path);
            if (node->subnodes) {
                /* VIRTUAL NODE */
                node_t *subnode, *subnode_tmp;
                /* Set virtual */
                xml_node_attr_add(crt_node, BAD_CAST "virtual", BAD_CAST "yes");
                /* Set size */
                strBuffSize = asprintf(&strBuff, "%u",
                                       HASH_COUNT(node->subnodes));
                if (0 < strBuffSize) {
                    xml_node_attr_cpy_add(crt_node, BAD_CAST "size", strBuff);
                    free(strBuff);
                }
                strBuff = NULL;
                /* Add subnodes */
                xml_node_ptr subnodes_node =
                    xml_node_child_new(crt_node, NULL,
                                       BAD_CAST "subnodes", NULL);
                xml_node_ptr subnode_node;
                HASH_ITER(hh, node->subnodes, subnode, subnode_tmp) {
                    subnode_node = xml_node_child_new(subnodes_node, NULL,
                                                      BAD_CAST "node", NULL);
                    insert_xml_node(subnode_node, subnode, full_hwloc_path);
                }
            }
        }
        /* Add links and connexions */
        edge_t *edge, *edge_tmp;
        HASH_ITER(hh, node->edges, edge, edge_tmp) {
            /* Check if edge belongs to no partition */
            if (edge_belongs_to_a_partition(edge, len_partitions))
                continue;
            crt_node = xml_node_child_new(cons_node, NULL,
                                          BAD_CAST "connexion", NULL);
            insert_xml_edge(crt_node, edge, node);
        }
    }
    if (!xml_node_has_child(nodes_node)
        && !xml_node_has_child(cons_node)) {
        /* No extra needed: remove it from the output */
        xml_node_free(part_node);
    } else {
        /* Set size */
        strBuffSize = asprintf(&strBuff, "%u", part_size);
        if (0 < strBuffSize) {
            xml_node_attr_cpy_add(explicit_node, BAD_CAST "size", strBuff);
            free(strBuff);
        }
        strBuff = NULL;
        xml_node_child_add(network_node, part_node);
    }
    return NETLOC_SUCCESS;
}

int netloc_write_xml_file(node_t *nodes, const UT_array *partitions,
                          const char *subnet, const char *path,
                          const char *hwlocpath,
                          const netloc_network_type_t transportType)
{
    xml_doc_ptr doc = NULL;        /* document pointer */
    xml_node_ptr root_node = NULL; /* root pointer */
    xml_node_ptr network_node = NULL;
    xml_char *buff = NULL;
    char *strBuff = NULL, *full_hwloc_path = NULL;
    int strBuffSize = 0, ret = NETLOC_ERROR;

    XML_LIB_CHECK_VERSION;

    /*
     * Add topology definition tag
     */
    /* Creates a new document, a machine node and set it as a root node. */
    doc = xml_doc_new(BAD_CAST "1.0");
    root_node = xml_node_new(NULL, BAD_CAST "machine");
    xml_doc_set_root_element(doc, root_node);
    /* Set version */
    xml_node_attr_add(root_node, BAD_CAST "version",
                      BAD_CAST NETLOC_STR_VERS(NETLOCFILE_VERSION_2_0));
    /* Add hwloc_path node */
    DIR* dir;
    if (hwlocpath && 0 < strlen(hwlocpath)) {
        if ('/' != hwlocpath[0]) {
            if (0 > asprintf(&full_hwloc_path, "%s/%s", path, hwlocpath))
                full_hwloc_path = NULL;
        } else {
            full_hwloc_path = strdup(hwlocpath);
        }
    }
    if (full_hwloc_path && 0 < strlen(full_hwloc_path)
        && (dir = opendir(full_hwloc_path))) {
        buff = xml_char_strdup(hwlocpath);
        if (buff)
            xml_node_child_new(root_node, NULL, BAD_CAST "hwloc_path", buff);
        xml_char_free(buff); buff = NULL;
        closedir(dir);
    }
    /* Add a network tag */
    network_node = xml_node_child_new(root_node, NULL,
                                      BAD_CAST "network", NULL);
    /* Set transport */
    xml_node_attr_add(network_node, BAD_CAST "transport",
                      BAD_CAST netloc_network_type_encode(transportType));
    /* Add subnet node */
    if (subnet && 0 < strlen(subnet)) {
        buff = xml_char_strdup(subnet);
        if (buff)
            xml_node_child_new(network_node, NULL, BAD_CAST "subnet", buff);
        xml_char_free(buff); buff = NULL;
    }
    /* Add partitions */
    int npartitions = utarray_len(partitions);
    char **ppartition = (char **)utarray_front(partitions);
    for (int p = 0; p < npartitions; ++p) {
        unsigned int part_size = 0;
        xml_node_ptr part_node = NULL, crt_node = NULL, nodes_node = NULL,
            cons_node = NULL, explicit_node = NULL;
        part_node = xml_node_child_new(network_node, NULL,
                                       BAD_CAST "partition", NULL);
        /* Set name */
        if (ppartition && 0 < strlen(*ppartition)) {
            xml_node_attr_cpy_add(part_node, BAD_CAST "name", *ppartition);
        }
        /* Add explicit */
        explicit_node = xml_node_child_new(part_node, NULL,
                                        BAD_CAST "explicit", NULL);
        /* Add nodes */
        nodes_node = xml_node_child_new(explicit_node, NULL,
                                        BAD_CAST "nodes", NULL);
        cons_node = xml_node_child_new(explicit_node, NULL,
                                       BAD_CAST "connexions", NULL);
        node_t *node, *node_tmp;
        HASH_ITER(hh, nodes, node, node_tmp) {
            /* Check node belongs to the current partition */
            if (!node->partitions || !node->partitions[p])
                continue;
            else
                ++part_size;
            crt_node = xml_node_child_new(nodes_node, NULL,
                                          BAD_CAST "node", NULL);
            insert_xml_node(crt_node, node, full_hwloc_path);
            if (node->subnodes) {
                /* VIRTUAL NODE */
                node_t *subnode, *subnode_tmp;
                /* Set virtual */
                xml_node_attr_add(crt_node, BAD_CAST "virtual", BAD_CAST "yes");
                /* Set size */
                strBuffSize = asprintf(&strBuff, "%u",
                                       HASH_COUNT(node->subnodes));
                if (0 < strBuffSize) {
                    xml_node_attr_cpy_add(crt_node, BAD_CAST "size", strBuff);
                    free(strBuff);
                }
                strBuff = NULL;
                /* Add subnodes */
                xml_node_ptr subnodes_node =
                    xml_node_child_new(crt_node, NULL,
                                       BAD_CAST "subnodes", NULL);
                xml_node_ptr subnode_node;
                HASH_ITER(hh, node->subnodes, subnode, subnode_tmp) {
                    subnode_node = xml_node_child_new(subnodes_node, NULL,
                                                      BAD_CAST "node", NULL);
                    insert_xml_node(subnode_node, subnode, full_hwloc_path);
                }
            }
            /* Add links and connexions */
            edge_t *edge, *edge_tmp;
            HASH_ITER(hh, node->edges, edge, edge_tmp) {
                /* Check edge belongs to this partition */
                if(!edge->partitions || !edge->partitions[p])
                    continue;
                crt_node = xml_node_child_new(cons_node, NULL,
                                              BAD_CAST "connexion", NULL);
                insert_xml_edge(crt_node, edge, node);
            }
        }
        /* Set size */
        strBuffSize = asprintf(&strBuff, "%u", part_size);
        if (0 < strBuffSize) {
            xml_node_attr_cpy_add(explicit_node, BAD_CAST "size", strBuff);
            free(strBuff);
        }
        strBuff = NULL;
        /* Get next partition */
        ppartition = (char **)utarray_next(partitions, ppartition);
    }
    /*
     * Add structural/extra edges
     */
    insert_extra(network_node, full_hwloc_path, utarray_len(partitions));
    /*
     * Dumping document to stdio or file
     */
    char *output_path;
    if (0 > asprintf(&output_path, "%s/IB-%s-nodes.xml", path, subnet))
        output_path = NULL;
    if (-1 == xml_doc_write(output_path, doc, "UTF-8", 1))
        fprintf(stderr, "Error: Unable to write to file \"%s\"\n", output_path);
    else
        ret = NETLOC_SUCCESS;
    /* Free path */
    free(output_path); free(full_hwloc_path);
    /* Free the document */
    xml_doc_free(doc);
    /*
     * Free the global variables that may
     * have been allocated by the parser.
     */
    xml_parser_cleanup();

    return ret;
}
