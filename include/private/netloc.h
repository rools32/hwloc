/* -*- encoding: utf-8 -*- */
/*
 * Copyright © 2014 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2013-2014 University of Wisconsin-La Crosse.
 *                         All rights reserved.
 * Copyright © 2015-2017 Inria.  All rights reserved.
 *
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 * See COPYING in top-level directory.
 *
 * $HEADER$
 */

#ifndef _NETLOC_PRIVATE_H_
#define _NETLOC_PRIVATE_H_

#include <hwloc.h>
#include <netloc.h>
#include <netloc/uthash.h>
#include <netloc/utarray.h>
#include <private/autogen/config.h>

#include <inttypes.h>

#define NETLOC_QUOTE(numver) # numver
#define NETLOC_STR_VERS(numver) NETLOC_QUOTE(numver)
#define NETLOCFILE_VERSION 1
#define NETLOCFILE_VERSION_2_0 2.0

#ifdef NETLOC_SCOTCH
#include <stdint.h>
#include <scotch.h>
typedef SCOTCH_Num NETLOC_int;
#else
typedef int64_t NETLOC_int;
#endif

/*
 * "Import" a few things from hwloc
 */
#define __netloc_attribute_unused __hwloc_attribute_unused
#define __netloc_attribute_malloc __hwloc_attribute_malloc
#define __netloc_attribute_const __hwloc_attribute_const
#define __netloc_attribute_pure __hwloc_attribute_pure
#define __netloc_attribute_deprecated __hwloc_attribute_deprecated
#define __netloc_attribute_may_alias __hwloc_attribute_may_alias
#define NETLOC_DECLSPEC HWLOC_DECLSPEC


/**********************************************************************
 * Types
 **********************************************************************/

/**
 * Definitions for Comparators
 * \sa These are the return values from the following functions:
 *     netloc_network_compare, netloc_dt_edge_t_compare, netloc_dt_node_t_compare
 */
typedef enum {
    NETLOC_CMP_SAME    =  0,  /**< Compared as the Same */
    NETLOC_CMP_SIMILAR = -1,  /**< Compared as Similar, but not the Same */
    NETLOC_CMP_DIFF    = -2,  /**< Compared as Different */
} netloc_compare_type_t;

/**
 * Enumerated type for the various types of supported networks
 */
typedef enum {
    NETLOC_NETWORK_TYPE_INVALID     = 0, /**< Invalid network */
    NETLOC_NETWORK_TYPE_ETHERNET    = 1, /**< Ethernet network */
    NETLOC_NETWORK_TYPE_INFINIBAND  = 2, /**< InfiniBand network */
} netloc_network_type_t;

/**
 * Enumerated type for the various types of supported topologies
 */
typedef enum {
    NETLOC_TOPOLOGY_TYPE_INVALID  = 0,  /**< Invalid */
    NETLOC_TOPOLOGY_TYPE_TREE     = 1,  /**< Tree */
    NETLOC_TOPOLOGY_TYPE_TORUS    = 2,  /**< Torus */
    NETLOC_TOPOLOGY_TYPE_EXPLICIT = 3,  /**< Explicit */
} netloc_topology_type_t;

/**
 * Enumerated type for the various types of nodes
 */
typedef enum {
    NETLOC_NODE_TYPE_INVALID = 0, /**< Invalid node */
    NETLOC_NODE_TYPE_HOST    = 1, /**< Host (a.k.a., network addressable endpoint - e.g., MAC Address) node */
    NETLOC_NODE_TYPE_SWITCH  = 2, /**< Switch node */
} netloc_node_type_t;

typedef enum {
    NETLOC_ARCH_TREE    =  0,  /* Fat tree */
} netloc_arch_type_t;


/* Pre declarations to avoid inter dependency problems */
/** \cond IGNORE */
struct netloc_machine_t;
typedef struct netloc_machine_t netloc_machine_t;
struct netloc_partition_t;
typedef struct netloc_partition_t netloc_partition_t;
struct netloc_network_explicit_t;
typedef struct netloc_network_explicit_t netloc_network_explicit_t;
struct netloc_node_t;
typedef struct netloc_node_t netloc_node_t;
struct netloc_edge_t;
typedef struct netloc_edge_t netloc_edge_t;
struct netloc_physical_link_t;
typedef struct netloc_physical_link_t netloc_physical_link_t;
struct netloc_path_t;
typedef struct netloc_path_t netloc_path_t;
struct netloc_hwloc_topology_t;
typedef struct netloc_hwloc_topology_t netloc_hwloc_topology_t;

struct netloc_network_t;
typedef struct netloc_network_t netloc_network_t;
/* To be changed in order to create a type to be derived */
typedef void netloc_topology_t;

struct netloc_arch_tree_t;
typedef struct netloc_arch_tree_t netloc_arch_tree_t;
struct netloc_arch_node_t;
typedef struct netloc_arch_node_t netloc_arch_node_t;
struct netloc_arch_node_slot_t;
typedef struct netloc_arch_node_slot_t netloc_arch_node_slot_t;
struct netloc_arch_t;
typedef struct netloc_arch_t netloc_arch_t;

struct netloc_allocation_t;
typedef struct netloc_allocation_t netloc_allocation_t;
struct netloc_res_t;
typedef struct netloc_res_t netloc_res_t;
/** \endcond */

/**
 * \struct netloc_machine_t
 * \brief Netloc Machine Description
 */
struct netloc_machine_t {
    /** Topology path */
    char *topopath;

    /** Partition List */
    netloc_partition_t *partitions; /* Hash table of partitions by name */

    /** current user's allocation */
    netloc_allocation_t *allocation;
};

/**
 * \struct netloc_partition_t
 * \brief Netloc Partition Type
 *
 * This data structure represents the partition, i.e., a set of nodes.
 */
struct netloc_partition_t {
    UT_hash_handle hh;    /* makes this structure hashable with name */
    unsigned int id;      /* rank in hashtable linked list */
    char *name;           /* Partition's name */
    netloc_arch_t *arch;  /* Abstract topology */
    UT_array *nodes;      /* Array of partition nodes */
    UT_array *edges;      /* Array of partition edges */
};

/**
 * \struct netloc_network_t
 * \brief Common Netloc Network Description
 *
 * This the common parts for each kind of netloc topologies.
 *
 * \note Must be initialized within the specific network constructor function.
 */
struct netloc_network_t {
    /** Type of the graph */
    netloc_topology_type_t type;

    /* Physical Transport Type */
    netloc_network_type_t transport_type;
};

/**
 * \struct netloc_network_explicit_t
 * \brief Netloc Explicit Network Description
 *
 * An opaque data structure used to reference a network explicit topology.
 *
 * \note Must be initialized with \ref netloc_network_explicit_construct()
 */
struct netloc_network_explicit_t {
    netloc_network_t parent;

    /** Topology path */
    char *topopath; /* To be removed */

    /** Partition List */
    netloc_partition_t *partitions; /* Hash table of partitions by name */

    /** Subnet ID */
    char *subnet_id;

    /** Node List */
    netloc_node_t *nodes; /* Hash table of nodes by physical_id */
    netloc_node_t *nodesByHostname; /* Hash table of nodes by hostname */

    /** Physical Link List */
    netloc_physical_link_t *physical_links; /* Hash table with physical links */

    /** Hwloc topology List */
    char *hwloc_dir_path;
    unsigned int nb_hwloc_topos;
    char **hwlocpaths;
    hwloc_topology_t *hwloc_topos;
};

/**
 * \brief Netloc Node Type
 *
 * Represents the concept of a node (a.k.a., vertex, endpoint) within a network
 * graph. This could be a server or a network switch. The \ref node_type parameter
 * will distinguish the exact type of node this represents in the graph.
 */
struct netloc_node_t {
    UT_hash_handle hh;       /* makes this structure hashable with physical_id */
    UT_hash_handle hh2;      /* makes this structure hashable with hostname */

    /** Physical ID of the node */
    char physical_id[20];

    /** Logical ID of the node (if any) */
    long logical_id;

    /** Type of the node */
    netloc_node_type_t type;

    /** Pointer to physical_links */
    UT_array *physical_links;

    /** Array of partitions this node is part of */
    UT_array *partitions;

    /** Description information from discovery (if any) */
    char *description;

    /** Outgoing edges from this node */
    netloc_edge_t *edges;

    /**
     *  The number of subnodes in the node->subnodes array.  If
     *  nsubnodes > 0, this node is a virtual one with subnodes,
     *  node->subnodes must be not NULL.  If nsubnodes == 0 and
     *  virtual_node != NULL, the current node is a node abstracted by
     *  the virtual node pointed by node->virtual_node.  If node is
     *  not virtual nor a subnode, node->virtual_node must equals NULL
     *  and node->nsubnodes must equals 0.
     */
    unsigned int nsubnodes;
    union {
        netloc_node_t **subnodes; /**< The group of nodes for the virtual nodes */
        netloc_node_t *virtual_node; /**< The parent node in case it is a virtual subnode */
    };

    netloc_path_t *paths;

    char *hostname;

    /** Hwloc topology */
    size_t hwloc_topo_idx;

    /**
     * Application-given private data pointer.
     * Initialized to NULL, and not used by the netloc library.
     */
    void * userdata;
};

/**
 * \brief Netloc Edge Type
 *
 * Represents the concept of a directed edge within a network graph.
 *
 * \note We do not point to the netloc_node_t structure directly to
 * simplify the representation, and allow the information to more easily
 * be entered into the data store without circular references.
 * \todo JJH Is the note above still true?
 */
struct netloc_edge_t {
    UT_hash_handle hh;       /* makes this structure hashable */

    netloc_node_t *dest;

    int id;

    /** Array of partitions this edge is part of **/
    UT_array *partitions;

    /** Pointers to the parent node */
    netloc_node_t *node;

    /** Pointer to physical_links */
    UT_array *physical_links;

    /** total gbits of the links */
    float total_gbits;

    unsigned int nsubedges;
    netloc_edge_t **subnode_edges; /* for edges going to / coming from virtual nodes */

    netloc_edge_t *other_way;

    /**
     * Application-given private data pointer.
     * Initialized to NULL, and not used by the netloc library.
     */
    void *userdata;
};

struct netloc_physical_link_t {
    UT_hash_handle hh;       /* makes this structure hashable */

    unsigned long long int id;
    netloc_node_t *src;
    netloc_node_t *dest;
    int ports[2];
    char *width;
    char *speed;

    netloc_edge_t *edge;

    unsigned long long int other_way_id;
    struct netloc_physical_link_t *other_way;

    /** gbits of the link from speed and width */
    float gbits;

    /** Description information from discovery (if any) */
    char *description;

    /** Array of partitions this physical_link is part of */
    UT_array *partitions;
};

struct netloc_path_t {
    UT_hash_handle hh;       /* makes this structure hashable */
    char dest_id[20];
    UT_array *links;
};

/**
 * \brief Hwloc Topology for Netloc Nodes
 *
 * Represents the Hwloc Topology for each Netloc Node, but hashable in
 * order to be able to find it in the \ref netloc_network_explicit_t
 * structure.
 */
struct netloc_hwloc_topology_t {
    UT_hash_handle hh;       /* makes this structure hashable */
    char *path;              /**< Topology filepath */
    size_t hwloc_topo_idx;
};

/**********************************************************************
 *        Architecture structures
 **********************************************************************/
struct netloc_allocation_t {
    netloc_res_t *res;
    /* TODO : Add things needed */
};

struct netloc_res_t {
    netloc_topology_t *toporef;
    int num_elems;
    int *idx; /**< Array of size num_elems. Contain cores indices */
    int *costs; /**< Array of size \ref toporef->num_dims. Contain comm costs */
    netloc_res_t *subres;
};

struct netloc_arch_tree_t {
    NETLOC_int num_levels;
    NETLOC_int *degrees;
    NETLOC_int *costs;
};

struct netloc_arch_node_t {
    UT_hash_handle hh;       /* makes this structure hashable */
    char *name; /* Hash key */
    netloc_node_t *node; /* Corresponding node */
    int idx_in_topo; /* idx with ghost hosts to have complete topo */
    int num_slots; /* it is not the real number of slots but the maximum slot idx */
    int *slot_idx; /* corresponding idx in slot_tree */
    int *slot_os_idx; /* corresponding os index for each leaf in tree */
    netloc_arch_tree_t *slot_tree; /* Tree built from hwloc */
    int num_current_slots; /* Number of PUs */
    NETLOC_int *current_slots; /* indices in the complete tree */
    int *slot_ranks; /* corresponding MPI rank for each leaf in tree */
};

struct netloc_arch_node_slot_t {
    netloc_arch_node_t *node;
    int slot;
};

struct netloc_arch_t {
    netloc_network_explicit_t *topology;
    int has_slots; /* if slots are included in the architecture */
    netloc_arch_type_t type;
    union {
        netloc_arch_tree_t *node_tree;
        netloc_arch_tree_t *global_tree;
    } arch;
    netloc_arch_node_t *nodes_by_name;
    netloc_arch_node_slot_t *node_slot_by_idx; /* node_slot by index in complete topo */
    NETLOC_int num_current_hosts; /* if has_slots, host is a slot, else host is a node */
    NETLOC_int *current_hosts; /* indices in the complete topology */
};

/**********************************************************************
 * Topology Functions
 **********************************************************************/
/**
 * Allocate a topology handle.
 *
 * User is responsible for calling \ref netloc_detach on the topology
 * handle.  The network parameter information is deep copied into the
 * topology handle, so the user may destruct the network handle after
 * calling this function and/or reuse the network handle.
 *
 * \returns A newly allocated pointer to the topology information on
 *          success.
 * \returns NULL upon an error.
 */
extern netloc_network_explicit_t *
netloc_network_explicit_construct();

/**
 * Destruct a topology handle
 *
 * \param topology A valid pointer to a \ref netloc_network_explicit_t
 * handle created from a prior call to \ref
 * netloc_network_explicit_construct.
 *
 * \returns NETLOC_SUCCESS on success
 * \returns NETLOC_ERROR upon an error.
 */
int netloc_network_explicit_destruct(netloc_network_explicit_t *topology);

int
netloc_network_explicit_find_reverse_edges(netloc_network_explicit_t *topology);

int netloc_network_explicit_read_hwloc(netloc_network_explicit_t *topology,
                                   int num_nodes, netloc_node_t **node_list);

#define netloc_network_explicit_iter_partitions(topology,partition,_tmp) \
    HASH_ITER(hh, (topology)->partitions, partition, _tmp)

#define netloc_network_explicit_iter_name_hwloctopos(topology,hwloctoponame) \
    for (unsigned int __idx = 0; __idx < (topology)->nb_hwloc_topos     \
             && ((hwloctoponame) = (topology)->hwlocpaths[__idx]);      \
         (hwloctoponame) = (topology)->hwlocpaths[__idx++])

#define netloc_network_explicit_iter_hwloctopos(topology,hwloctopo) \
    for (unsigned int __idx = 0; __idx < (topology)->nb_hwloc_topos \
             && ((hwloctopo) = (topology)->hwloc_topos[__idx]);     \
         (hwloctopo) = (topology)->hwloc_topos[__idx++])

#define netloc_network_explicit_find_node(topology,node_id,node)    \
    HASH_FIND_STR((topology)->nodes, node_id, node)

#define netloc_network_explicit_iter_nodes(topology,node,_tmp)  \
    HASH_ITER(hh, (topology)->nodes, node, _tmp)

#define netloc_network_explicit_num_nodes(topology) \
    HASH_COUNT((topology)->nodes)


/*************************************************/


/**
 * Constructor for netloc_partition_t
 *
 * User is responsible for calling the destructor on the handle.
 *
 * \param id New partition's id in the hashtable in \ref
 * netloc_network_explicit_t \param name A pointer to a valid string
 * which correspond to the partition's name
 *
 * Returns
 *   A newly allocated pointer to the partition information.
 */
netloc_partition_t *netloc_partition_construct(const unsigned int id,
                                               const char *name);

/**
 * Destructor for netloc_partition_t
 *
 * \param partition A valid partition handle
 *
 * Returns
 *   NETLOC_SUCCESS on success
 *   NETLOC_ERROR on error
 */
int netloc_partition_destruct(netloc_partition_t *partition);

#define netloc_partition_iter_nodes(partition, pnode)                   \
    netloc_iter_nodelist((partition)->nodes, pnode)

#define netloc_partition_iter_edges(partition, pedge)                   \
    netloc_iter_edgelist((partition)->edges, pedge)

/*************************************************/


/**
 * Constructor for netloc_node_t
 *
 * User is responsible for calling the destructor on the handle.
 *
 * Returns
 *   A newly allocated pointer to the node information.
 */
netloc_node_t *netloc_node_construct(void);

/**
 * Destructor for netloc_node_t
 *
 * \param node A valid node handle
 *
 * Returns
 *   NETLOC_SUCCESS on success
 *   NETLOC_ERROR on error
 */
int netloc_node_destruct(netloc_node_t *node);

char *netloc_node_pretty_print(const netloc_node_t *node);

#define netloc_node_get_num_subnodes(node) \
    (node)->nsubnodes

#define netloc_node_get_subnode(node,i) \
    (node)->subnodes[(i)]

#define netloc_node_get_num_edges(node) \
    utarray_len((node)->edges)

#define netloc_node_get_edge(node,i) \
    (*(netloc_edge_t **)utarray_eltptr((node)->edges, (i)))

#define netloc_node_iter_edges(node,edge,_tmp) \
    HASH_ITER(hh, (node)->edges, edge, _tmp)

#define netloc_node_iter_paths(node,path,_tmp) \
    HASH_ITER(hh, (node)->paths, path, _tmp)

#define netloc_node_is_host(node) \
    ((node)->type == NETLOC_NODE_TYPE_HOST)

#define netloc_node_is_switch(node) \
    ((node)->type == NETLOC_NODE_TYPE_SWITCH)

#define netloc_node_iter_paths(node, path,_tmp) \
    HASH_ITER(hh, (node)->paths, path, _tmp)

int netloc_node_is_in_partition(const netloc_node_t *node,
                                const netloc_partition_t *partition);

/*************************************************/

/**
 * Constructor for netloc_edge_t
 *
 * User is responsible for calling the destructor on the handle.
 *
 * Returns
 *   A newly allocated pointer to the edge information.
 */
netloc_edge_t *netloc_edge_construct();

/**
 * Destructor for netloc_edge_t
 *
 * \param edge A valid edge handle
 *
 * Returns
 *   NETLOC_SUCCESS on success
 *   NETLOC_ERROR on error
 */
int netloc_edge_destruct(netloc_edge_t *edge);

char * netloc_edge_pretty_print(const netloc_edge_t* edge);

void netloc_edge_reset_uid(void);

int netloc_edge_is_in_partition(const netloc_edge_t *edge,
                                const netloc_partition_t *partition);

#define netloc_edge_get_num_links(edge) \
    utarray_len((edge)->physical_links)

#define netloc_edge_get_link(edge,i) \
    (*(netloc_physical_link_t **)utarray_eltptr((edge)->physical_links, (i)))

#define netloc_edge_get_num_subedges(edge) \
    ((edge)->nsubedges)

#define netloc_edge_get_subedge(edge,i) \
    ((edge)->subnode_edges[(i)])

/*************************************************/


/**
 * Constructor for netloc_physical_link_t
 *
 * User is responsible for calling the destructor on the handle.
 *
 * Returns
 *   A newly allocated pointer to the physical link information.
 */
netloc_physical_link_t * netloc_physical_link_construct(void);


/**
 * Copy constructor for netloc_physical_link_t
 *
 * User is responsible for calling the destructor on the handle.  The
 * newly allocated physical link has the same informations as \ref
 * origin.  All strings and \ref UT_array attributes are dupplicated.
 *
 * \param origin A valid physical link to be copied
 *
 * Returns
 *   A newly allocated pointer to the physical link information.
 */
netloc_physical_link_t * netloc_physical_link_deep_copy(netloc_physical_link_t *origin);

/**
 * Destructor for netloc_physical_link_t
 *
 * Returns
 *   NETLOC_SUCCESS on success
 *   NETLOC_ERROR on error
 */
int netloc_physical_link_destruct(netloc_physical_link_t *link);

char * netloc_link_pretty_print(netloc_physical_link_t* link);

/*************************************************/


netloc_path_t *netloc_path_construct(void);
int netloc_path_destruct(netloc_path_t *path);


/**********************************************************************
 *        Architecture functions
 **********************************************************************/

netloc_arch_t * netloc_arch_construct(void);

int netloc_arch_destruct(netloc_arch_t *arch);

netloc_arch_node_t *netloc_arch_node_construct(void);

int netloc_arch_build(netloc_arch_t *arch, int add_slots);

int netloc_arch_set_current_resources(netloc_arch_t *arch);

int netloc_arch_set_global_resources(netloc_arch_t *arch);

int netloc_arch_node_get_hwloc_info(netloc_arch_node_t *arch,
                                    netloc_network_explicit_t *topology);

void netloc_arch_tree_complete(netloc_arch_tree_t *tree,
                               UT_array **down_degrees_by_level,
                               int num_hosts, int **parch_idx);

NETLOC_int netloc_arch_tree_num_leaves(netloc_arch_tree_t *tree);


/**********************************************************************
 *        Access functions of various elements of the topology
 **********************************************************************/

#define netloc_get_num_partitions(object) \
    utarray_len((object)->partitions)

#define netloc_get_partition_id(object,i) \
    ((*(netloc_partition_t **)utarray_eltptr((object)->partitions, (i)))->id)

#define netloc_path_iter_links(path,link)                               \
    for(netloc_physical_link_t **link = (netloc_physical_link_t **)     \
            utarray_front((path)->links);                               \
         (link) != NULL;                                                \
         link = (netloc_physical_link_t **)utarray_next((path)->links, link))

#define netloc_iter_nodelist(nl,pnode)                                  \
    for(netloc_node_t **pnode = (netloc_node_t **)utarray_front(nl);    \
        (pnode) != NULL;                                                \
        pnode = (netloc_node_t **)utarray_next(nl,pnode))

#define netloc_iter_edgelist(el,pedge)                                  \
    for(netloc_edge_t **pedge = (netloc_edge_t **)utarray_front(el);    \
        (pedge) != NULL;                                                \
        pedge = (netloc_edge_t **)utarray_next(el,pedge))

/**********************************************************************
 *        Misc functions
 **********************************************************************/

/**
 * Decode the network type
 *
 * \param net_type A valid member of the \ref netloc_network_type_t type
 *
 * \returns NULL if the type is invalid
 * \returns A string for that \ref netloc_network_type_t type
 */
static inline const char *
netloc_network_type_encode(const netloc_network_type_t net_type) {
    if( NETLOC_NETWORK_TYPE_ETHERNET == net_type ) {
        return "ETH";
    }
    else if( NETLOC_NETWORK_TYPE_INFINIBAND == net_type ) {
        return "IB";
    }
    else {
        return NULL;
    }
}

/**
 * Encode the network type
 *
 * \param net_type_str The network type as read from the XML topology file.
 *
 * \returns A valid member of the \ref netloc_network_type_t type
 */
static inline netloc_network_type_t
netloc_network_type_decode(const char *net_type_str) {
    if( !strcmp(net_type_str, "ETH") ) {
        return NETLOC_NETWORK_TYPE_ETHERNET;
    }
    else if( !strcmp(net_type_str, "IB") ) {
        return NETLOC_NETWORK_TYPE_INFINIBAND;
    }
    else {
        return NETLOC_NETWORK_TYPE_INVALID;
    }
}

/**
 * Decode the node type
 *
 * \param node_type A valid member of the \ref netloc_node_type_t type
 *
 * \returns NULL if the type is invalid
 * \returns A string for that \ref netloc_node_type_t type
 */
static inline const char *
netloc_node_type_encode(const netloc_node_type_t node_type) {
    if( NETLOC_NODE_TYPE_SWITCH == node_type ) {
        return "SW";
    }
    else if( NETLOC_NODE_TYPE_HOST == node_type ) {
        return "CA";
    }
    else {
        return NULL;
    }
}

/**
 * Encode the node type
 *
 * \param node_type_str The node type as read from the XML topology file.
 *
 * \returns A valid member of the \ref netloc_node_type_t type
 */
static inline netloc_node_type_t
netloc_node_type_decode(const char * node_type_str) {
    if( !strcmp(node_type_str, "SW") ) {
        return NETLOC_NODE_TYPE_SWITCH;
    }
    else if( !strcmp(node_type_str, "CA") ) {
        return NETLOC_NODE_TYPE_HOST;
    }
    else {
        return NETLOC_NODE_TYPE_INVALID;
    }
}

ssize_t netloc_line_get(char **lineptr, size_t *n, FILE *stream);

char *netloc_line_get_next_token(char **string, char c);

int netloc_build_comm_mat(char *filename, int *pn, double ***pmat);

#define STRDUP_IF_NOT_NULL(str) (NULL == (str) ? NULL : strdup(str))
#define STR_EMPTY_IF_NULL(str) (NULL == (str) ? "" : str)

#endif // _NETLOC_PRIVATE_H_
