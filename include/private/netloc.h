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

#ifndef PRIVATE_NETLOC_H
#define PRIVATE_NETLOC_H

#include <string.h>

#include "utils/uthash.h"
#include "utils/utarray.h"

#include <netloc.h>
#include <hwloc.h>

/* Pre declarations to avoid inter dependency problems */
/** \cond IGNORE */
struct netloc_machine_t;
typedef struct netloc_machine_t netloc_machine_t;
struct netloc_partition_t;
typedef struct netloc_partition_t netloc_partition_t;

struct netloc_deco_t;
typedef struct netloc_deco_t netloc_deco_t;

struct netloc_topology_t;
typedef struct netloc_topology_t netloc_topology_t;

struct netloc_explicit_t;
typedef struct netloc_explicit_t netloc_explicit_t;
struct netloc_position_t;
typedef struct netloc_position_t netloc_position_t;

struct netloc_node_t;
typedef struct netloc_node_t netloc_node_t;
struct netloc_edge_t;
typedef struct netloc_edge_t netloc_edge_t;
struct netloc_physical_link_t;
typedef struct netloc_physical_link_t netloc_physical_link_t;
/** \endcond */

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


#define NETLOC_SUCCESS 0
#define NETLOC_ERROR 1


/**********************************************************************
 * Types
 **********************************************************************/

struct netloc_machine_t {
    char *topopath;

    /** Hwloc topology List */
    char *hwloc_dir_path;
    char **hwlocpaths;
    unsigned int nb_hwloc_topos;
    //hwloc_topology_t *hwloc_topos; // TODO
    // TODO move hwloc* in explicit

    netloc_partition_t *partitions;
    int npartitions; /* rename into num_partitions */

    netloc_explicit_t *explicit;

};

/**
 * Enumerated type for the various types of supported networks
 */
typedef enum {
    NETLOC_NETWORK_TYPE_INVALID     = 0, /**< Invalid network */
    NETLOC_NETWORK_TYPE_ETHERNET    = 1, /**< Ethernet network */
    NETLOC_NETWORK_TYPE_INFINIBAND  = 2, /**< InfiniBand network */
    /* TODO add new types */
} netloc_network_type_t;

static inline netloc_network_type_t
netloc_network_type_decode(const char * network_type_str) {
    if( !strcmp(network_type_str, "IB") ) {
        return NETLOC_NETWORK_TYPE_INFINIBAND;
    }
    else if( !strcmp(network_type_str, "ETH") ) {
        return NETLOC_NETWORK_TYPE_ETHERNET;
    }
    else {
        return NETLOC_NETWORK_TYPE_INVALID;
    }
}

/**
 * Enumerated type for the various types of supported topologies
 */
typedef enum {
    NETLOC_TOPOLOGY_TYPE_INVALID  = 0,  /**< Invalid */
    NETLOC_TOPOLOGY_TYPE_RANDOM   = 1,  /**< Random */
    NETLOC_TOPOLOGY_TYPE_RING     = 2,  /**< Ring */
    NETLOC_TOPOLOGY_TYPE_GRID     = 3,  /**< Grid */
    NETLOC_TOPOLOGY_TYPE_ALL2ALL  = 4,  /**< All2All */
    NETLOC_TOPOLOGY_TYPE_TREE     = 5,  /**< Tree */
    NETLOC_TOPOLOGY_TYPE_TORUS    = 6,  /**< Torus */
} netloc_topology_type_t;

/**
 * Enumerated type for the various types of nodes
 */
typedef enum {
    NETLOC_NODE_TYPE_INVALID = 0, /**< Invalid node */
    NETLOC_NODE_TYPE_HOST    = 1, /**< Host (a.k.a., network addressable endpoint - e.g., MAC Address) node */
    NETLOC_NODE_TYPE_SWITCH  = 2, /**< Switch node */
} netloc_node_type_t;

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

struct netloc_explicit_t {
    netloc_node_t *nodes; /* hash table of nodes by name
                             // TODO add by physical id */
    netloc_physical_link_t *physical_links; /* hash table of nodes by name and by physical id */

    netloc_deco_t *deco;
};

struct netloc_partition_t {
    /* Physical Transport Type */
    netloc_network_type_t transport_type;

    char *subnet; /** Subnet ID */
    int idx;
    char *partition_name;
    int num_hosts;
    netloc_topology_t *topology;
};

struct netloc_deco_t {
    int nnodes;
    int *edge_idx;
    int *edges;
    int *edge_costs;
};

struct netloc_topology_t {
    netloc_topology_type_t type;

    int ndims;
    int *dimensions;
    NETLOC_int *costs;

    /* For hierarchical topologies */
    netloc_topology_t *subtopo;
};

struct netloc_position_t {
    int *coords; /* coords in the topo */
    int idx; /* idx in the topo */
};

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
    UT_array physical_links;

    /** List of partitions */
    int nparts;
    int *newpartitions;

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
        netloc_node_t *virtual_node; /**< The parent node in case it is a not virtual subnode */
    };

    netloc_position_t *newtopo_positions; /* Postition in topology in partition */
    int deco_position; /* Position in deco topology */

    // netloc_path_t *paths; // TODO

    char *hostname;

    /** Hwloc topology */
    int long hwloc_topo_idx;

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

    /** Arraypartitions this edge is part of */
    int nparts;
    int *newpartitions;

    /** Pointers to the parent node */
    netloc_node_t *node;

    /** Pointer to physical_links */
    UT_array physical_links;

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

    /* gbits of the link from speed and width */
    float gbits;

    /* Description information from discovery (if any) */
    char *description;

    /* Array of partitions this physical_link is part of */
    int nparts;
    int *newpartitions;
};

struct netloc_hwloc_topology_t;
typedef struct netloc_hwloc_topology_t netloc_hwloc_topology_t;
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





netloc_machine_t *netloc_machine_construct(char *topopath);

int netloc_machine_add_partitions(netloc_machine_t *machine,
        int npartitions, netloc_partition_t *partitions);
int netloc_machine_add_explicit(netloc_machine_t *machine);

netloc_topology_t * netloc_topology_construct(void);

netloc_explicit_t * netloc_explicit_construct(void);
int netloc_explicit_add_node( netloc_explicit_t *explicit, netloc_node_t *node);

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
 * Destructor for netloc_physical_link_t
 *
 * Returns
 *   NETLOC_SUCCESS on success
 *   NETLOC_ERROR on error
 */
int netloc_physical_link_destruct(netloc_physical_link_t *link);

char * netloc_link_pretty_print(netloc_physical_link_t* link);

#define netloc_machine_iter_nodes(machine, node, _tmp) \
    HASH_ITER(hh, (machine)->explicit->nodes, node, _tmp)

#define netloc_node_iter_edges(node,edge,_tmp) \
    HASH_ITER(hh, (node)->edges, edge, _tmp)

#define netloc_node_is_host(node) \
    ((node)->type == NETLOC_NODE_TYPE_HOST)

#define netloc_node_is_switch(node)             \
    ((node)->type == NETLOC_NODE_TYPE_SWITCH)

#define netloc_edge_is_virtual(edge) \
    (0 < (edge)->nsubedges)

#define netloc_edge_get_num_links(edge)         \
    utarray_len(&(edge)->physical_links)

#define netloc_edge_get_link(edge,i)                                    \
    (*(netloc_physical_link_t **)utarray_eltptr(&(edge)->physical_links, (i)))

// TODO supprimer utarray pour structures définitives
#endif /* !PRIVATE_NETLOC_H */
