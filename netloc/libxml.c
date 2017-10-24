/* -*- encoding: utf-8 -*- */
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

#define _GNU_SOURCE	   /* See feature_test_macros(7) */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <libgen.h>

#include <private/autogen/config.h>
#include <private/netloc.h>
#include <private/netloc-xml.h>

#if defined(HWLOC_HAVE_LIBXML2)

/**
 * Load the netloc node as described in the xml file, of which
 * \ref it_node is a valid pointer to a DOM element.
 *
 * The returned element is to be added to the \ref
 * netloc_topology_t. If the \ref netloc_node_t returned has nsubnodes
 * > 0, this means that the node is virtual. The subnodes (contained
 * in the node->subnodes array) have to be added before the virtual
 * node to ease the hashtable liberation.
 *
 * \param it_node A valid XML DOM node pointing to the proper <node> tag
 * \param hwlocpath The path to the directory containing the hwloc 
 *                  topology files
 * \param hwloc_topos A valid pointer to the hwloc_topos field in
 *                    \ref netloc_topology_t
 *
 * Returns
 *   A newly allocated and initialized pointer to the node information.
 */
static netloc_node_t *
netloc_node_xml_load(xmlNode *it_node, char *hwlocpath,
                     netloc_hwloc_topology_t **hwloc_topos);

/**
 * Load the netloc edge as described in the xml file, of which
 * \ref it_edge is a valid pointer to a DOM element.
 *
 * The returned element is to be added to the corresponding \ref
 * netloc_node_t. The node has to be already part of the \ref
 * netloc_topology_t
 *
 * \param it_edge A valid XML DOM node pointing to the proper <connexion> tag
 * \param topology A valid pointer to the current topology being loaded
 * \param partition A valid pointer to the current partition being loaded
 *
 * Returns
 *   A newly allocated and initialized pointer to the edge information.
 */
static netloc_edge_t *
netloc_edge_xml_load(xmlNode *it_edge, netloc_topology_t *topology,
                     netloc_partition_t *partition);

/**
 * Load the netloc physical link as described in the xml file, of which
 * \ref it_link is a valid pointer to a DOM element.
 *
 * The returned element is to be added to the \ref netloc_edge_t.
 *
 * \param it_link A valid XML DOM node pointing to the proper <link> tag
 * \param edge A valid pointer to the current edge being loaded
 * \param partition A valid pointer to the current partition being loaded
 *
 * Returns
 *   A newly allocated and initialized pointer to the physical link information.
 */
static netloc_physical_link_t *
netloc_physical_link_xml_load(xmlNode *it_link, netloc_edge_t *edge,
                              netloc_partition_t *partition);

static xmlDoc *netloc_xml_reader_init(char *path);

static int netloc_xml_reader_clean_and_out(xmlDoc *doc);

int netloc_topology_libxml_load(char *path, netloc_topology_t **ptopology)
{
    xmlNode *machine_node, *root_node = NULL, *crt_node = NULL;
    xmlChar *buff = NULL;
    int num_nodes = 0;
    netloc_topology_t *topology = NULL;
    netloc_hwloc_topology_t *hwloc_topos = NULL;

    if (NULL == ptopology) {
        fprintf(stderr, "ERROR: Invalid pointer given as parameter\n");
        return NETLOC_ERROR;
    }
    if (NULL == path || 0 >= strlen(path)) {
        fprintf(stderr, "ERROR: invalid path given (%s)\n", path);
        return NETLOC_ERROR_NOENT;
    }

    topology = netloc_topology_construct();
    if (NULL == topology)
        return NETLOC_ERROR;

    xmlDoc *doc = netloc_xml_reader_init(path);
    if (NULL == doc) {
        return (netloc_topology_destruct(topology), NETLOC_ERROR_NOENT);
    }
    
    machine_node = xmlDocGetRootElement(doc);
    if (machine_node && !strcmp("machine", (char *) machine_node->name)) {
        /* Check netloc file version */
        buff = xmlGetProp(machine_node, BAD_CAST "version");
        if (!buff ||
            0 != strcmp(NETLOC_STR_VERS(NETLOCFILE_VERSION_2_0),(char *)buff)) {
            fprintf(stderr, "Incorrect version number (\"%s\"), "
                    "please generate your input file again.\n", (char *)buff);
            xmlFree(buff); buff = NULL;
            netloc_topology_destruct(topology); topology = NULL;
            goto clean_and_out;
        }
        xmlFree(buff); buff = NULL;
    } else {
        fprintf(stderr, "Cannot read the machine in %s.\n", path);
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }
    /* Retreive hwloc path */
    char *hwlocpath = NULL;
    if ((crt_node = machine_node->children)
        && !strcmp("hwloc_path", (char *)crt_node->name)
        && crt_node->children && crt_node->children->content) {
        hwlocpath = strdup((char *)crt_node->children->content);
    } else {
        fprintf(stderr, "Cannot read hwloc path in %s\n", path);
        crt_node = crt_node->prev;
    }
    if (hwlocpath) {
        DIR *hwlocdir;
        char *realhwlocpath;
        if (hwlocpath[0] != '/') {
            char *path_tmp = strdup(path);
            asprintf(&realhwlocpath, "%s/%s", dirname(path_tmp), hwlocpath);
            free(path_tmp);
            hwlocpath = realhwlocpath;
        }
        if (!(hwlocdir = opendir(hwlocpath))) {
            fprintf(stderr, "Couldn't open hwloc directory: \"%s\"\n",
                    hwlocpath);
            perror("opendir");
            netloc_topology_destruct(topology);
            topology = NULL;
            goto clean_and_out;
        } else {
            closedir(hwlocdir);
        }
    }
    /* Retreive network tag */
    if (!(root_node = (!strcmp((char *)crt_node->name, "hwloc_path")
                       ? crt_node->next : crt_node))
        || 0 != strcmp((char *)root_node->name, "network")) {
        fprintf(stderr, "Cannot read the topology in %s.\n", path);
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }
    netloc_network_type_t transport_type;
    /* Check transport type */
    buff = xmlGetProp(root_node, BAD_CAST "transport");
    if (!buff) {
        fprintf(stderr, "Transport type not found, please generate "
                "your input file again.\n");
        xmlFree(buff); buff = NULL;
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    } else if(NETLOC_NETWORK_TYPE_INVALID ==
              (transport_type = netloc_network_type_decode((const char*)buff))){
        fprintf(stderr, "Invalid network type (\"%s\"), please generate your "
                "input file again.\n", (char *)buff);
        xmlFree(buff); buff = NULL;
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }
    xmlFree(buff); buff = NULL;
    /* Retreive subnet */
    char *subnet = NULL;
    if (root_node->children && (crt_node = root_node->children)
        && !strcmp("subnet", (char *)crt_node->name)
        && crt_node->children && crt_node->children->content) {
        subnet = strdup((char *)crt_node->children->content);
    } else {
        fprintf(stderr, "Cannot read the subnet in %s\n", path);
        netloc_topology_destruct(topology); topology = NULL;
        goto clean_and_out;
    }

    /* Read partitions from file */

    for (xmlNode *part = crt_node->next;
         part  && !strcmp("partition", (char *)part->name) && part->children;
         part = part->next) {

        /* Check partition's size */
        long int nnodes = 0;
        char *strBuff;
        buff = xmlGetProp(part, BAD_CAST "size");
        if (!buff || (!(nnodes = strtol((char *)buff, &strBuff, 10))
                      && strBuff == (char *)buff)){
            fprintf(stderr, "WARN: cannot read partition's size.\n");
        }
        xmlFree(buff); buff = NULL; strBuff = NULL;
        num_nodes += (int)nnodes;

        /* Check partition's name */
        netloc_partition_t *partition;
        buff = xmlGetProp(part, BAD_CAST "name");
        if (!buff || !strlen((char *)buff)) {
            fprintf(stderr, "WARN: cannot read partition's name.\n");
            if (!buff)
                buff = BAD_CAST "";
        }
        if ('/' == *(char *)buff) { /* Exclude /extra+structural/ partition */
            partition = NULL;
        } else {
            partition =
                netloc_partition_construct(HASH_COUNT(topology->partitions),
                                           (char *)buff);
            HASH_ADD_STR(topology->partitions, name, partition);
        }
        if ('\0' != *(char *)buff)
            xmlFree(buff);
        buff = NULL;

        /* Read nodes from file */

        /* Check for <nodes> tag */
        if (!(crt_node = part->children)
            || 0 != strcmp("nodes", (char *)crt_node->name)
            || (!crt_node->children && 0 < nnodes)) {
            fprintf(stderr, "WARN: No \"nodes\" tag, but %ld nodes required.\n",
                    nnodes);
            continue;
        }
        for (xmlNode *it_node = crt_node->children;
             it_node;
             it_node = it_node->next) {
            netloc_node_t *node = NULL;
            /* Prefetch physical_id to know if it's worth loading the node */
            buff = xmlGetProp(it_node, BAD_CAST "mac_addr");
            if (!buff) {
                continue;
            }
            HASH_FIND_STR(topology->nodes, (char *)buff, node);
            if (!node) {
                node = netloc_node_xml_load(it_node, hwlocpath, &hwloc_topos);
                if (!node) {
                    fprintf(stderr, "WARN: node cannot be loaded. Skipped\n");
                    continue;
                }
                /* Add to the hashtables */
                HASH_ADD_STR(topology->nodes, physical_id, node);
                for (unsigned int n = 0; n < node->nsubnodes; ++n) {
                    HASH_ADD_STR(topology->nodes, physical_id,
                                 node->subnodes[n]);
                }
                if (NETLOC_NODE_TYPE_HOST == node->type
                    && 0 < strlen(node->hostname)) {
                    HASH_ADD_KEYPTR(hh2, topology->nodesByHostname,
                                    node->hostname,
                                    strlen(node->hostname), node);
                }
            }
            /* Add to the partition */
            if (partition) {
                for (unsigned int n = 0; n < node->nsubnodes; ++n) {
                    utarray_push_back(node->subnodes[n]->partitions,
                                      &partition);
                }
                utarray_push_back(partition->nodes, &node);
                utarray_push_back(node->partitions, &partition);
            }
        }
        if (partition && utarray_len(partition->nodes) != nnodes) {
            fprintf(stderr, "WARN: Found %u nodes, but %ld required.\n",
                    utarray_len(partition->nodes), nnodes);
            num_nodes -= nnodes;
            num_nodes += utarray_len(partition->nodes);
        }

        /* Read edges from file */

        /* Check for <connexions> tag */
        if (!(crt_node = crt_node->next)
            || 0 != strcmp("connexions", (char *)crt_node->name)
            || !crt_node->children) {
            if (1 < nnodes)
                fprintf(stderr, "WARN: No \"connexions\" tag.\n");
            continue;
        }
        for (xmlNode *it_edge = crt_node->children;
             it_edge;
             it_edge = it_edge->next) {
            netloc_edge_t *edge =
                netloc_edge_xml_load(it_edge, topology, partition);
            if (partition && edge) {
                utarray_push_back(partition->edges, &edge);
            }
        }
    }

    /* Set topology->physical_links->other_way */
    netloc_physical_link_t *plink = NULL,
        *plink_tmp = NULL,
        *plink_found = NULL;
    HASH_ITER(hh, topology->physical_links, plink, plink_tmp) {
        HASH_FIND(hh, topology->physical_links, &plink->other_way_id,
                  sizeof(unsigned long long int), plink_found);
        if (NULL == plink_found) {
            fprintf(stderr, "WARN: Strangely enough, the corresponding reverse "
                    "physical link seems to be absent...\n");
        } else {
            plink->other_way = plink_found;
            if (NULL == plink->edge->other_way)
                plink->edge->other_way = plink_found->edge;
        }
    }

    /* Change from hashtable to array for hwloc topologies */
    topology->nb_hwloc_topos = HASH_COUNT(hwloc_topos);
    if (0 < topology->nb_hwloc_topos) {
        topology->hwlocpaths = malloc(sizeof(char *[topology->nb_hwloc_topos]));
        netloc_hwloc_topology_t *ptr, *ptr_tmp;
        HASH_ITER(hh, hwloc_topos, ptr, ptr_tmp) {
            topology->hwlocpaths[ptr->hwloc_topo_idx] = ptr->path;
            HASH_DEL(hwloc_topos, ptr);
            free(ptr);
        }
    } else {
        fprintf(stderr, "WARN: No hwloc topology found\n");
    }

    topology->topopath       = path;
    topology->hwloc_dir_path = strdup(hwlocpath);
    topology->subnet_id      = strdup(subnet);
    topology->transport_type = transport_type;

    if (netloc_topology_find_reverse_edges(topology) != NETLOC_SUCCESS) {
        netloc_topology_destruct(topology);
        topology = NULL;
        goto clean_and_out;
    }
    
 clean_and_out:
    free(subnet);
    free(hwlocpath);
    netloc_xml_reader_clean_and_out(doc);
    *ptopology = topology;
    
    return NETLOC_SUCCESS;
}

static netloc_node_t *
netloc_node_xml_load(xmlNode *it_node, char *hwlocpath,
                     netloc_hwloc_topology_t **hwloc_topos) {
    xmlNode *tmp = NULL;
    xmlChar *buff = NULL;
    char *strBuff = NULL;
    size_t strBuffSize, buffSize;
    netloc_node_t *node = netloc_node_construct();
    /* read hostname */
    buff = xmlGetProp(it_node, BAD_CAST "name");
    if (buff && 0 < strlen((char *)buff)) {
        strBuff = strdup((char *)buff);
    } else {
        strBuff = strdup("");
    }
    xmlFree(buff); buff = NULL;
    /* set physical_id */
    buff = xmlGetProp(it_node, BAD_CAST "mac_addr");
    if (buff && 0 < strlen((char *)buff)) {
        strncpy(node->physical_id, (char *)buff, 20);
        /* Should be shorter than 20 */
        node->physical_id[19] = '\0'; /* If a problem occurs */
        xmlFree(buff); buff = NULL;
    } else {
        fprintf(stderr, "Error: node \"%s\" has no physical address and "
                "is not added to the topology.\n",
                strBuff && strlen(strBuff) ? strBuff : "(no name)");
        xmlFree(buff); free(strBuff);
        netloc_node_destruct(node);
        return NULL;
    }
    /* set hostname */
    node->hostname = strBuff; strBuff = NULL;
    /* set type (i.e., host or switch) */
    buff = xmlGetProp(it_node, BAD_CAST "type");
    if (buff)
        node->type = netloc_node_type_decode((char *)buff);
    xmlFree(buff); buff = NULL;
    /* Set description */
    if (it_node->children && (tmp = it_node->children)
        && 0 == strcmp("description", (char *)tmp->name)
        && tmp->children && tmp->children->content) {
        node->description = strdup((char *)tmp->children->content);
    }
    /* set hwloc topology field iif node is a host */
    if (NETLOC_NODE_TYPE_HOST == node->type
        && (buff = xmlGetProp(it_node, BAD_CAST "hwloc_file"))
        && 0 < (buffSize = strlen((char *)buff))) {
        netloc_hwloc_topology_t *hwloc_topo = NULL;
        char *refname;
        strBuffSize = asprintf(&strBuff, "%s/%s", hwlocpath, (char *)buff);
        if (5 > strBuffSize) { /* bad return from asprintf() */
            fprintf(stderr, "WARN: Invalid topology file \"%s/%s\", or "
                    "memory exhaustion\n", hwlocpath, (char *)buff);
        } else if (9 < strBuffSize
                   && 0 == strcmp(".diff.xml", &strBuff[strBuffSize-9])) {
            /* hwloc_file point to a diff file */
            hwloc_topology_diff_t diff;
            if (0 <= hwloc_topology_diff_load_xml(strBuff, &diff, &refname)
                && refname) {
                /* Load diff file to check on refname */
                hwloc_topology_diff_destroy(diff);
                free(strBuff);
                strBuffSize = asprintf(&strBuff, "%s/%s", hwlocpath, refname);
                free(refname);
            } else {
                fprintf(stderr,"WARN: no refname for topology file \"%s/%s\"\n",
                        hwlocpath, (char *)buff);
            }
        }
        HASH_FIND(hh, *hwloc_topos, strBuff, (unsigned)strBuffSize, hwloc_topo);
        if (!hwloc_topo) {
            /* The topology cannot be retrieved in the hashtable */
            size_t hwloc_topo_idx = (size_t)HASH_COUNT(*hwloc_topos);
            hwloc_topo = malloc(sizeof(netloc_hwloc_topology_t));
            hwloc_topo->path = strdup(strBuff);
            hwloc_topo->hwloc_topo_idx = hwloc_topo_idx;
            node->hwloc_topo_idx = hwloc_topo_idx;
            ++hwloc_topo_idx;
            HASH_ADD_STR(*hwloc_topos, path, hwloc_topo);
        } else {
            node->hwloc_topo_idx = hwloc_topo->hwloc_topo_idx;
        }
        free(strBuff); strBuff = NULL;
        xmlFree(buff); buff = NULL;
    } else if (NETLOC_NODE_TYPE_SWITCH == node->type
               && (buff = xmlGetProp(it_node, BAD_CAST "virtual"))
               && 0 < (buffSize = strlen((char *)buff))
               && 0 == strncmp("yes", (char *)buff, 3)) {
        /* Virtual node */
        xmlFree(buff); buff = NULL;
        buff = xmlGetProp(it_node, BAD_CAST "size");
        if (1 != sscanf((const char *)buff, "%u", &node->nsubnodes)) {
            fprintf(stderr, "WARN: Cannot read how many subnodes are included "
                    "into the virtual node \"%s\"\n", node->physical_id);
        }
        xmlFree(buff); buff = NULL;
        /* Add subnodes */
        if (!node->description) {
            tmp = it_node->children;
            node->description = strndup(node->physical_id, 20);
        } else {
            tmp = tmp->next;
        }
        if (0 != strcmp("subnodes", (char *)tmp->name)) {
            fprintf(stderr, "WARN: virtual node \"%s\" is empty, and thus, "
                    "ignored\n", node->physical_id);
            netloc_node_destruct(node);
            return NULL;
        }
        /* Allocate subnodes array */
        node->subnodes = malloc(sizeof(netloc_node_t *[node->nsubnodes]));
        if (!node->subnodes) {
            fprintf(stderr, "WARN: unable to allocate the memory for virtual "
                    "node \"%s\" subnodes. This node is thus ignored\n",
                    node->physical_id);
            netloc_node_destruct(node);
            return NULL;
        }
        unsigned int subnode_id = 0;
        for (xmlNode *it_subnode = tmp->children;
             it_subnode;
             it_subnode = it_subnode->next) {
            netloc_node_t *subnode =
                netloc_node_xml_load(it_subnode, hwlocpath, hwloc_topos);
            if (subnode)
                subnode->virtual_node = node;
            node->subnodes[subnode_id++] = subnode;
        }
        /* Check we found all the subnodes */
        if (subnode_id != node->nsubnodes) {
            fprintf(stderr, "WARN: expecting %u subnodes, but %u found\n",
                    node->nsubnodes, subnode_id);
        }
    }
    return node;
}

static netloc_edge_t *
netloc_edge_xml_load(xmlNode *it_edge, netloc_topology_t *topology,
                     netloc_partition_t *partition)
{
    xmlNode *tmp, *crt_node;
    xmlChar *buff = NULL;
    char *strBuff = NULL;
    size_t strBuffSize;
    netloc_edge_t *edge = netloc_edge_construct();
    /* set total_gbits */
    float total_gbits;
    buff = xmlGetProp(it_edge, BAD_CAST "bandwidth");
    if (buff && 0 < strlen((char *)buff)) {
        total_gbits = strtof((char *)buff, &strBuff);
        if (0 == total_gbits && strBuff == (char *)buff)
            fprintf(stderr, "WARN: cannot read connexion's bandwidth.\n");
        xmlFree(buff); buff = NULL; strBuff = NULL;
        edge->total_gbits = total_gbits;
    }
    /* get number of links */
    unsigned int nlinks;
    buff = xmlGetProp(it_edge, BAD_CAST "nblinks");
    if (!buff || (1 > sscanf((char *)buff, "%u", &nlinks))) {
        fprintf(stderr, "WARN: cannot read connexion's physical links.\n");
    } else if (0 >= nlinks) {
        fprintf(stderr, "WARN: less than 1 connexion's physical link required "
                "(%u).\n", nlinks);
    }
    xmlFree(buff); buff = NULL; strBuff = NULL;
    /* Move tmp to the proper xml node and set src node */
    if ((tmp = it_edge->children) && 0 == strcmp("src", (char *)tmp->name)
        && tmp->children && tmp->children->content) {
        netloc_topology_find_node(topology,
                                  (char *)tmp->children->content, edge->node);
    } else {
        fprintf(stderr, "ERROR: cannot find connexion's source node.\n");
        goto ERROR;
    }
    /* Move tmp to the proper xml node and set dest node */
    if ((tmp = tmp->next) && 0 == strcmp("dest", (char *)tmp->name)
        && tmp->children && tmp->children->content) {
        netloc_topology_find_node(topology,
                                  (char *)tmp->children->content, edge->dest);
    } else {
        fprintf(stderr, "ERROR: cannot find connexion's destination node.\n");
        goto ERROR;
    }
    /* Add edge to its node if it does not already exists */
    netloc_edge_t *edge_tmp = NULL;
    HASH_FIND_PTR(edge->node->edges, &edge->dest, edge_tmp);
    if (NULL == edge_tmp) {
        HASH_ADD_PTR(edge->node->edges, dest, edge);
        /* Set partition */
        if (partition)
            utarray_push_back(edge->partitions, &partition);
    } else {
        /* Set partition */
        if (partition) {
            utarray_push_back(edge_tmp->partitions, &partition);
            for (unsigned int se = 0; se < edge_tmp->nsubedges; ++se)
                utarray_push_back(edge_tmp->subnode_edges[se]->partitions,
                                  &partition);
        }
        /* Edge already created from another partition */
        netloc_edge_destruct(edge);
        return edge_tmp;
    }

    if ((buff = xmlGetProp(it_edge, BAD_CAST "virtual"))
        && 0 < (strBuffSize = strlen((char *)buff))
        && 0 == strncmp("yes", (char *)buff, 3)) {
        /*** VIRTUAL EDGE ***/
        xmlFree(buff); buff = NULL;
        /* Move tmp to the proper xml node */
        unsigned int nsubedges;
        if (!(tmp = tmp->next) || 0 != strcmp("subconnexions", (char*)tmp->name)
            || !tmp->children) {
            fprintf(stderr, "ERROR: cannot find the subedges. Failing to read "
                    "this connexion\n");
            goto ERROR;
        }
        buff = xmlGetProp(tmp, BAD_CAST "size");
        if (!buff || (1 > sscanf((char *)buff, "%u", &nsubedges))) {
            fprintf(stderr, "ERROR: cannot read virtual edge subnodes.\n");
            goto ERROR;
        } else if (2 > nsubedges) {
            fprintf(stderr, "WARN: less than 2 edges (%u).\n", nsubedges);
        }
        edge->nsubedges = nsubedges;
        edge->subnode_edges = (netloc_edge_t **)
            malloc(sizeof(netloc_edge_t *[nsubedges]));
        xmlFree(buff); buff = NULL; strBuff = NULL;
        unsigned int se = 0;
        for(xmlNode *it_subedge = tmp->children;
                it_subedge;
                it_subedge = it_subedge->next) {
            netloc_edge_t *subedge =
                netloc_edge_xml_load(it_subedge, topology, partition);
            edge->subnode_edges[se++] = subedge;
            if (!subedge) {
                fprintf(stderr, "WARN: cannot read subconnexion #%u\n", se);
                continue;
            }
            total_gbits -= subedge->total_gbits;
            utarray_concat(edge->node->physical_links, subedge->physical_links);
            utarray_concat(edge->physical_links, subedge->physical_links);
        }
    } else {

        /* Read physical links from file */

        /* Check for <links> tag */
        if (!(crt_node = tmp->next)
            || 0 != strcmp("links", (char *)crt_node->name)
            || !crt_node->children) {
            fprintf(stderr, "ERROR: No \"links\" tag.\n");
            goto ERROR;
        }
        xmlNode *it_link;
        netloc_physical_link_t *link = NULL;
        for (it_link = crt_node->children;
             it_link;
             it_link = it_link->next) {
            link = netloc_physical_link_xml_load(it_link, edge, partition);
            if (link) {
                total_gbits -= link->gbits;
                utarray_push_back(edge->node->physical_links, &link);
                utarray_push_back(edge->physical_links, &link);
                HASH_ADD(hh, topology->physical_links, id,
                         sizeof(unsigned long long int), link);
            }
        }
    }
#ifdef NETLOC_DEBUG
    /* Check proper value for edge->total_gbits */
    if (0 != total_gbits) {
        fprintf(stderr, "WARN: Erroneous value read from file for edge total "
                "bandwidth. \"%f\" instead of %f (calculated).\n",
                edge->total_gbits, edge->total_gbits - total_gbits);
    }
    /* Check proper value for nlinks and utarray_len(edge->physical_links) */
    if (nlinks != utarray_len(edge->physical_links)) {
        fprintf(stderr, "WARN: Erroneous value read from file for edge count "
                "of physical links. %u requested, but only %u found\n",
                nlinks, utarray_len(edge->physical_links));
    }
#endif /* NETLOC_DEBUG */
    return edge;
 ERROR:
    netloc_edge_destruct(edge);
    return NULL;
}

static netloc_physical_link_t *
netloc_physical_link_xml_load(xmlNode *it_link, netloc_edge_t *edge,
                              netloc_partition_t *partition)
{
    xmlChar *buff = NULL;
    char *strBuff = NULL;
    netloc_physical_link_t *link = netloc_physical_link_construct();
    /* set ports */
    int tmpport;
    buff = xmlGetProp(it_link, BAD_CAST "srcport");
    if (!buff ||
        (!(tmpport = strtol((char *)buff, &strBuff, 10))
         && strBuff == (char *)buff)){
        fprintf(stderr, "ERROR: cannot read physical link's source port.\n");
        goto ERROR;
    }
    xmlFree(buff); buff = NULL;
    link->ports[0] = tmpport;
    buff = xmlGetProp(it_link, BAD_CAST "destport");
    if (!buff ||
        (!(tmpport = strtol((char *)buff, &strBuff, 10))
         && strBuff == (char *)buff)){
        fprintf(stderr,
                "ERROR: cannot read physical link's destination port.\n");
        goto ERROR;
    }
    xmlFree(buff); buff = NULL;
    link->ports[1] = tmpport;
    /* set speed */
    buff = xmlGetProp(it_link, BAD_CAST "speed");
    if (!buff || 0 >= strlen((char *)buff)) {
        fprintf(stderr, "ERROR: cannot read physical link's speed.\n");
        goto ERROR;
    }
    link->speed = strdup((char *)buff);
    xmlFree(buff); buff = NULL;
    /* set width */
    buff = xmlGetProp(it_link, BAD_CAST "width");
    if (!buff || 0 >= strlen((char *)buff)) {
        fprintf(stderr, "ERROR: cannot read physical link's width.\n");
        goto ERROR;
    }
    link->width = strdup((char *)buff);
    xmlFree(buff); buff = NULL;
    /* set gbits */
    float gbits;
    buff = xmlGetProp(it_link, BAD_CAST "bandwidth");
    if (!buff || 0 >= strlen((char *)buff)
        || (!(gbits = strtof((char *)buff, &strBuff))
            && strBuff == (char *)buff)) {
        fprintf(stderr, "ERROR: cannot read physical link's bandwidth.\n");
        goto ERROR;
    }
    xmlFree(buff); buff = NULL; strBuff = NULL;
    /* set id */
    unsigned long long int id_read;
    buff = xmlGetProp(it_link, BAD_CAST "logical_id");
    if (!buff || 0 >= strlen((char *)buff)
        || 1 > sscanf((char *)buff, "%llu", &id_read)) {
        fprintf(stderr, "ERROR: cannot read physical link's id.\n");
        goto ERROR;
    }
    link->id = id_read;
    xmlFree(buff); buff = NULL; strBuff = NULL;
    /* set other_way_id */
    buff = xmlGetProp(it_link, BAD_CAST "reverse_logical_id");
    if (!buff || 0 >= strlen((char *)buff)
        || 1 > sscanf((char *)buff, "%llu", &id_read)) {
        fprintf(stderr, "ERROR: cannot read reverse physical link's id.\n");
        goto ERROR;
    }
    link->other_way_id = id_read;
    xmlFree(buff); buff = NULL; strBuff = NULL;
    /* set description */
    if (it_link->children && it_link->children->content) {
        link->description = strdup((char *)it_link->children->content);
    }
    /* set src, dest, partition, edge */
    link->src   = edge->node;
    link->dest  = edge->dest;
    link->edge  = edge;
    link->gbits = gbits;
    if (partition)
        utarray_push_back(link->partitions, &partition);

    return link;

 ERROR:
    netloc_physical_link_destruct(link);
    xmlFree(buff); buff = NULL;
    return NULL;
}

static xmlDoc *netloc_xml_reader_init(char *path)
{
    xmlDoc *doc = NULL;

    /*
     * This initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION;

    doc = xmlReadFile(path, "UTF-8", XML_PARSE_NOBLANKS);
    if (!doc) {
        fprintf(stderr, "Cannot open topology file %s\n", path);
        perror("xmlReadFile");
    }

    return doc;
}

static int netloc_xml_reader_clean_and_out(xmlDoc *doc)
{
    /* Free the document */
    xmlFreeDoc(doc);

    /*
     * Free the global variables that may
     * have been allocated by the parser.
     */
    if (getenv("NETLOC_LIBXML_CLEANUP"))
        xmlCleanupParser();

    return NETLOC_SUCCESS;
}

#endif
