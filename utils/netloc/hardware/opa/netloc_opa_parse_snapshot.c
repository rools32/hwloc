/* -*- encoding: utf-8 -*- */
/*
 * Copyright © 2017-2018 Inria.  All rights reserved.
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

#include <private/netloc.h>
#include <private/autogen/config.h>
#include <private/netloc.h>
#include <private/netloc-xml.h>
#include <private/utils/xml.h>
#include <private/utils/netloc.h>
#include <netloc/utarray.h>
#include <netloc/uthash.h>
#include <private/utils/xml.h>

#define PARTSTRLEN 30
typedef struct partition_name {
    UT_hash_handle hh;         /* makes this structure hashable */
    char name[PARTSTRLEN];
    int id;
} partition_name;

static int load_nodes(xml_node_ptr root, utils_node_t **nodes,
        utils_physical_link_t **links, partition_name **partitions);
static int load_sms(xml_node_ptr root);
static int load_links(xml_node_ptr root, utils_node_t *nodes, utils_physical_link_t *all_links);
static int load_opa_snapshot(const char *path, utils_node_t **nodes);
static char *hostname_from_description(char *desc);
static int partition_id_from_hostname(char *hostname, partition_name **partitions);

int load_nodes(xml_node_ptr root, utils_node_t **nodes, utils_physical_link_t **links,
        partition_name **partitions)
{
    /* For each Node */
    for (size_t c = 0; c < xml_node_get_num_children(root); c++) {
        char *guid = NULL, *desc = NULL;
        char *portID = NULL, *subnet = NULL;
        netloc_node_type_t type = NETLOC_NODE_TYPE_INVALID;
        char *speed = NULL, *width = NULL;
        int portNum = 0;

        xml_node_ptr xnode = xml_node_get_child(root, c);

        if (!strcmp("Node", xml_node_get_name(xnode))) {
            /* For each node field */
            for (size_t d = 0; d < xml_node_get_num_children(xnode); d++) {
                xml_node_ptr node_info = xml_node_get_child(xnode, d);
                if (!strcmp("NodeGUID", xml_node_get_name(node_info))) {
                    guid = xml_node_get_content(node_info);

                } else if (!strcmp("NodeDesc", xml_node_get_name(node_info))) {
                    desc = xml_node_get_content(node_info);

                } else if (!strcmp("NodeType_Int",
                            xml_node_get_name(node_info))) {
                    int nodeTypeRaw = atoi(xml_node_get_content(node_info));
                    if (nodeTypeRaw == 1)
                        type = NETLOC_NODE_TYPE_HOST;
                    else
                        type = NETLOC_NODE_TYPE_SWITCH;

                } else if (!strcmp("PortInfo", xml_node_get_name(node_info))) {
                    portNum++;
                    portID = xml_node_attr_get(node_info, "id");
                    /* For each PorInfo field */
                    for (size_t e = 0;
                            e < xml_node_get_num_children(node_info); e++) {
                        xml_node_ptr port_info =
                            xml_node_get_child(node_info, e);

                        if (!strcmp("SubnetPrefix",
                                    xml_node_get_name(port_info))) {
                            subnet = xml_node_get_content(port_info);

                        } else if (!strcmp("LinkWidthActive_Int",
                                    xml_node_get_name(port_info))) {
                            width = xml_node_get_content(port_info);

                        } else if (!strcmp("LinkSpeedEnabled_Int",
                                    xml_node_get_name(port_info))) {
                            speed = xml_node_get_content(port_info);
                        }
                    }

                    /* Save the link in hash table of links */
                    assert(portID);
                    utils_physical_link_t *link;
                    char *str_id;
                    asprintf(&str_id, "%.6s:%.4s:%.4s:%.4s%s",
                            portID, portID+6, portID+10, portID+14, portID+18);
                    HASH_FIND_STR(*links, str_id, link);  /* id already in the hash? */
                    if (!link) {
                        link = (utils_physical_link_t *)
                            malloc(sizeof(utils_physical_link_t));
                        strncpy(link->str_id, str_id, MAX_STR);
                        link->width = width;
                        link->speed = speed;
                        link->subnet = subnet;
                        HASH_ADD_STR(*links, str_id, link);
                    } else {
                        fprintf(stderr, "Warning: link %s already found\n", portID);

                    }
                    free(str_id);
                }
            }
        } else {
            fprintf(stderr, "Error: malformed xml file in Nodes\n");
            return NETLOC_ERROR;
        }

        /* Check we got all info */
        if (!guid || !desc || !portID || !subnet || \
                type == NETLOC_NODE_TYPE_INVALID) {
            fprintf(stderr, "Error: incomplete definition for node %s\n",
                    guid? guid: "");
            return NETLOC_ERROR;
        }

        /* Everything is parsed, we add the node */
        char *id;
        utils_node_t *node;

        asprintf(&id, "%.6s:%.4s:%.4s:%.4s",
                guid, guid+6, guid+10, guid+14);

        /* For each found subnet TODO add loop */
        HASH_FIND_STR(*nodes, id, node);  /* id already in the hash? */
        if (!node) {
            size_t size = sizeof(*node)+sizeof(char)*(strlen(desc)+1);
            node = (utils_node_t *) malloc(size);
            sprintf(node->physical_id, "%s", id);
            node->logical_id = 0; // TODO
            node->type = type;
            node->edges = NULL;
            node->description = strdup(desc);
            if (type == NETLOC_NODE_TYPE_HOST) {
                node->hostname = hostname_from_description(desc);
                node->main_partition = partition_id_from_hostname(node->hostname, partitions);
            } else {
                node->hostname = NULL;
                node->main_partition = -1;
            }
            node->partitions = NULL;
            node->subnodes = NULL;
            node->port_num = portNum;


            utarray_new(node->physical_links, &utils_physical_link_icd);

            HASH_ADD_STR(*nodes, physical_id, node);
            printf("Node %s added\n", id);
        } else {
            fprintf(stderr, "Warning: node %s already parsed\n", id);
        }
    }

}

int load_sms(xml_node_ptr root)
{
}

int load_links(xml_node_ptr root, utils_node_t *nodes, utils_physical_link_t *all_links)
{
    int link_id = 0;
    /* For each Link */
    for (size_t c = 0; c < xml_node_get_num_children(root); c++) {
        xml_node_ptr xnode = xml_node_get_child(root, c);
        if (!strcmp("Link", xml_node_get_name(xnode))) {
            char *lid = xml_node_attr_get(xnode, "id");
            char *guids[2];
            char *ports[2];
            utils_node_t *lnodes[2];

            /* Look for the link in links */
            utils_physical_link_t *links[2];
            char *linkID;
            asprintf(&linkID, "%.6s:%.4s:%.4s:%.4s%s",
                    lid, lid+6, lid+10, lid+14, lid+18);
            HASH_FIND_STR(all_links, linkID, links[0]);
            assert(links[0]);

            /* For each link field: From and To */
            for (size_t d = 0; d < xml_node_get_num_children(xnode); d++) {
                xml_node_ptr link_info = xml_node_get_child(xnode, d);
                int type = 1;
                if (!strcmp("From", xml_node_get_name(link_info))) {
                    type = 0;
                }
                /* For each node info */
                for (size_t e = 0; e < xml_node_get_num_children(link_info); e++) {
                    xml_node_ptr node_info = xml_node_get_child(link_info, e);

                    /* NodeGUID */
                    if (!strcmp("NodeGUID", xml_node_get_name(node_info))) {
                        char *guid = xml_node_get_content(node_info);
                        asprintf(&guids[type], "%.6s:%.4s:%.4s:%.4s",
                                guid, guid+6, guid+10, guid+14);

                        /* Find nodes in node list */
                        HASH_FIND_STR(nodes, guids[type], lnodes[type]);
                        assert(lnodes[type]);

                    /* PortNum */
                    } else if (!strcmp("PortNum", xml_node_get_name(node_info))) {
                        ports[type] = xml_node_get_content(node_info);
                    }
                }
            }

            /* Find link in other way */
            char *other_linkID;
            asprintf(&other_linkID, "%s:%s", guids[1], ports[1]);
            HASH_FIND_STR(all_links, other_linkID, links[1]);
            assert(links[1]);

            /* Add new info for links */
            for (int way = 0; way < 2; way++) {
                utils_node_t *node = lnodes[way];
                utils_node_t *other_node = lnodes[!way];
                utils_physical_link_t *link = links[way];

                unsigned int port_idx = atoi(ports[way])-1;

                if (!node->physical_links) {
                    utarray_new(node->physical_links, &utils_physical_link_icd);
                }

                /* NB: there is no function to set a specific index */
                if (port_idx+1 > utarray_len(node->physical_links)) {
                    utarray_insert(node->physical_links, link, port_idx);
                } else {
                    utils_physical_link_t *dest_link = (utils_physical_link_t *)
                        utarray_eltptr(node->physical_links, port_idx);
                    memcpy(dest_link, link, sizeof(utils_physical_link_t));
                }

                /* Add the link to the edges of the node */
                utils_edge_t *edge;
                HASH_FIND_STR(node->edges, other_node->physical_id, edge);
                /* Creation of the edge */
                if (!edge) {
                    edge = (utils_edge_t *) malloc(sizeof(utils_edge_t));
                    strcpy(edge->dest, other_node->physical_id);
                    edge->total_gbits = 0;
                    edge->total_gbits += link->gbits;
                    edge->partitions =  NULL;
                    edge->subedges = NULL;
                    edge->reverse_edge = NULL;
                    utarray_new(edge->physical_link_idx, &ut_int_icd);
                    HASH_ADD_STR(node->edges, dest, edge);
                }

                link->int_id = link_id++;
                link->dest = other_node;
                link->parent_node = node;
                link->ports[0] =  atoi(ports[way]);
                link->ports[1] =  atoi(ports[!way]);
                link->parent_edge = edge;
                link->description = NULL;
                link->partitions = NULL;
                link->other_link = NULL;

                utarray_push_back(edge->physical_link_idx, &port_idx);
            }

            /* Add pointer to link in other way */
            for (int way = 0; way < 2; way++) {
                unsigned int other_port_idx = atoi(ports[way])-1;
                utils_node_t *other_node = lnodes[!way];

                utils_physical_link_t *other_link = (utils_physical_link_t *)
                    utarray_eltptr(other_node->physical_links, other_port_idx);
                links[way]->other_link = other_link;
            }



        }
    }
}

int load_opa_snapshot(const char *path, utils_node_t **nodes)
{
    int ret = NETLOC_ERROR;
    char *buff;

    xml_doc_ptr doc = NULL;
    doc = xml_node_read_file(path);

    xml_node_ptr snapshot_node = xml_doc_get_root_element(doc);
    if (NULL == snapshot_node) {
        if (netloc__xml_verbose())
            fprintf(stderr, "ERROR: unable to parse the XML file.\n");
        return NETLOC_ERROR_NOENT;
    }

    /* The node is not Snapshot */
    if (strcmp("Snapshot", xml_node_get_name(snapshot_node))) {
        fprintf(stderr, "Waiting Snapshot but got %s\n",
                xml_node_get_name(snapshot_node));
        goto ERROR;
    }
    if (0 >= xml_node_get_num_children(snapshot_node)) {
        fprintf(stderr, "Waiting children in Snapshot node\n");
        goto ERROR;
    }

    /* For each subnode of Snapshot */
    *nodes = NULL;
    utils_physical_link_t *links = NULL;
    partition_name *partitions = NULL;
    for (size_t c = 0; c < xml_node_get_num_children(snapshot_node); c++) {
        xml_node_ptr machine_node = xml_node_get_child(snapshot_node, c);
        if (!strcmp("Nodes", xml_node_get_name(machine_node))) {
            load_nodes(machine_node, nodes, &links, &partitions);

        } else if (!strcmp("SMs", xml_node_get_name(machine_node))) {
            load_sms(machine_node);

        } else if (!strcmp("Links", xml_node_get_name(machine_node))) {
            load_links(machine_node, *nodes, links);

        } else if (!strcmp("McMembers", xml_node_get_name(machine_node))) {
            /* Not used */
        }
    }

    return 0;
ERROR:
    fprintf(stderr, "Error: malformed xml file\n");
    // TODO free
    return -1;
}

static char *hostname_from_description(char *desc)
{
    int max_size = strlen(desc);
    char *hostname = (char *)malloc(max_size*sizeof(char));

    /* Looking for the name of the hostname */
    int i = 0;
    if (desc[0] == '\'')
        desc++;
    while (i < max_size &&
            ((desc[i] >= 'a' && desc[i] <= 'z') ||
             (desc[i] >= '0' && desc[i] <= '9') ||
             (desc[i] == '-'))) {
        hostname[i] = desc[i];
        i++;
    }
    hostname[i++] = '\0';
    char *old_hostname = hostname;
    hostname = realloc(hostname, i*sizeof(char));
    if (!hostname) {
        fprintf(stderr, "ERROR: cannot reallocate memory\n");
        hostname = old_hostname;
    }
    return hostname;
}

int partition_id_from_hostname(char *hostname, partition_name **partitions)
{
    partition_name *partition;
    HASH_FIND_INT(*partitions, hostname, partition);

    if (!partition) {
        partition = (partition_name *)malloc(sizeof(partition_name));
        partition->id = HASH_COUNT(*partitions);
        strncpy(partition->name, hostname,
                strlen(hostname)+1 < PARTSTRLEN? strlen(hostname)+1: PARTSTRLEN);
        HASH_ADD_STR(*partitions, name, partition);
    }

    return partition->id;
}


int main(int argc, char *argv[])
{
    char *path = argv[1];
    // TODO call opareport command
    /* File from opareport -s -r -o snapshot */
    utils_node_t *nodes;
    /* FIXME: Subnet seems to be not reliable in snapshot so a fake one is okay
     * for now. May be problematic when several subnets are present */
    char *subnet = "0x0000000000000000";
    load_opa_snapshot(path, &nodes);

    //netloc_network_explicit_set_partitions(nodes, &partitions, NULL);
    //char *outpath = NULL;
    //char *hwlocpath = NULL;
    //netloc_write_into_xml_file(nodes, &partitions, subnet, outpath,
    //        hwlocpath,
    //        NETLOC_NETWORK_TYPE_OMNIPATH);
    return 0;
}


/*

dom = minidom.parse('snapshot.xml') # opareport -s -r -o snapshot"

def fmtID(i):
    return re.sub(r'^0x(.{4})(.{4})(.{4})(.{4})', r'\1:\2:\3:\4', i)

HOST=0
SWITCH=1

domNodes = dom.getElementsByTagName("Nodes")[0]
nodes = {}
linksByID = {}
partitions = set()
subnets = set()

# Nodes
for node in domNodes.getElementsByTagName("Node"):
    guid = fmtID(node.getElementsByTagName("NodeGUID")[0].firstChild.nodeValue)
    description = node.getElementsByTagName("NodeDesc")[0].firstChild.nodeValue
    nodeTypeRaw = int(node.getElementsByTagName(
        "NodeType_Int")[0].firstChild.nodeValue)
    if nodeTypeRaw == 1:
        nodeType = HOST
    else:
        nodeType = SWITCH

    if nodeType == HOST:
        name = description.split()[0]
        try:
            partition = re.search('^([a-zA-Z-]+).*$', name).group(1)
            partitions.add(partition)
        except AttributeError:
            pass
    else:
        name = ''
        partition = ''

    ports = node.getElementsByTagName("PortInfo")
    numPorts = len(ports)
    for port in ports:
        portID = port.attributes["id"].nodeValue
        subnet = fmtID(port.getElementsByTagName("SubnetPrefix")[0]\
                .firstChild.nodeValue)
        if not subnet in nodes:
            nodes[subnet] = {}
        width = port.getElementsByTagName("LinkWidthActive_Int")[0]\
                .firstChild.nodeValue
        speed = port.getElementsByTagName("LinkSpeedEnabled_Int")[0]\
                .firstChild.nodeValue
        linksByID[portID] = {'subnet': subnet, 'width': width, 'speed': speed}

        if not guid in nodes[subnet]:
            nodes[subnet][guid] = {'id': guid, 'description': description,
                    'name': name, 'capacity': numPorts, 'type': nodeType,
                    'partition': [partition]}

for s,v in nodes.items():
    print("subnet %s, len %d" % (s, len(v)))


# Links
links = {}
allLinks = dom.getElementsByTagName("Links")[0]
linkID = 0
for l in allLinks.getElementsByTagName("Link"):
    link = []
    src = l.getElementsByTagName("From")[0]
    dst = l.getElementsByTagName("To")[0]
    linkGuid = l.attributes["id"].nodeValue

    # enable the found subnet
    subnet = linksByID[linkGuid]['subnet']
    subnets.add(subnet)
    if not subnet in links:
        links[subnet] = {}

    for port in [src, dst]:
        guid = fmtID(
                port.getElementsByTagName("NodeGUID")[0].firstChild.nodeValue)
        if not guid in nodes[subnet]:
            print("Oups: node %s not found but in link" % guid)
        portNum = port.getElementsByTagName("PortNum")[0].firstChild.nodeValue
        link.append({'id': guid, 'port': portNum})

    # save the link in both ways
    for first in (0, 1):
        src = link[first]['id']
        print(src)
        dst = link[1-first]['id']
        currLink = {
                'hosts': (link[first], link[1-first]),
                'id': 2*linkID+first,
                'otherid': 2*linkID+1-first,
                'width': linksByID[linkGuid]['width'],
                'speed': linksByID[linkGuid]['speed'],
                'gbits': 100}
        linkID += 1
        if src not in links[subnet]:
            links[subnet][src] = {}
        if dst not in links[subnet][src]:
            links[subnet][src][dst] = []
        links[subnet][src][dst].append(currLink)

################################################################################
# Write file
for subnet in subnets:
    with open('netloc/OPA-%s-nodes.txt' % subnet,'w') as f:
        # Version
        f.write("1\n") # Version
        f.write("omnipath\n") # Subnet
        f.write("\n") # Path to hwloc
        f.write("%d\n" % len(nodes[subnet])) # Number of nodes

        # Nodes
        for node in nodes[subnet].values():
            # phyID,logID,type,partition,description,hostname
            line = "%s,%s,%d,%d,%s,%s" % (\
                    node['id'], node['id'], node['type'], 0,
                    node['description'], node['name'])
            f.write(line+"\n")

        # Nodes
        for src, dstLink in links[subnet].items():
            line = "%s" % src
            for dst, link in links[subnet][src].items():
                numRepeats = len(link)
                speed = 100*numRepeats
                # src,dest,speed,partitions,numLinks,
                line += ",%s,%d,%d,%d" % (dst, speed, 0, numRepeats)
                for l in link:
                    # id,port1,port2,
                    # width,speed,gbits,desc,
                    # other_way_id,partitions
                    line += ",%d,%s,%s,%s,%s,%s,%s,%d,%d" % (\
                            l['id'], l['hosts'][0]['port'], l['hosts'][1]['port'],
                            l['width'], l['speed'], l['gbits'], '',
                            l['otherid'], 0)
            f.write(line+"\n")
        # Partitions
        f.write(','.join(partitions)+"\n")

# debug XXX XXX XXX XXX XXX XXX XXX
for subnet in subnets:
    nodeKeys = set(nodes[subnet].keys())
    linkKeys = set(links[subnet].keys())
    print(subnet)
    print(list(nodeKeys-linkKeys))

*/
