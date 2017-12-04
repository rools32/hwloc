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
#include <stdlib.h>

#include <private/autogen/config.h>
#include <private/netloc.h>

static int cur_uid = 0;

netloc_physical_link_t * netloc_physical_link_construct(void)
{
    netloc_physical_link_t *physical_link = NULL;

    physical_link = (netloc_physical_link_t*)
        malloc(sizeof(netloc_physical_link_t));
    if( NULL == physical_link ) {
        return NULL;
    }

    physical_link->id = cur_uid;
    cur_uid++;

    physical_link->src = NULL;
    physical_link->dest = NULL;

    physical_link->ports[0] = -1;
    physical_link->ports[1] = -1;

    physical_link->width = NULL;
    physical_link->speed = NULL;

    physical_link->edge = NULL;
    physical_link->other_way = NULL;

    utarray_new(physical_link->partitions, &ut_ptr_icd);

    physical_link->gbits = -1;

    physical_link->description = NULL;

    return physical_link;
}

netloc_physical_link_t * netloc_physical_link_deep_copy(netloc_physical_link_t *origin)
{
    netloc_physical_link_t *physical_link = NULL;

    if (NULL == origin) {
        return NULL;
    }

    physical_link = (netloc_physical_link_t*)
        malloc(sizeof(netloc_physical_link_t));
    if( NULL == physical_link ) {
        return NULL;
    }

    physical_link->id = cur_uid;
    cur_uid++;

    physical_link->src = origin->src;
    physical_link->dest = origin->dest;

    physical_link->ports[0] = origin->ports[0];
    physical_link->ports[1] = origin->ports[1];

    physical_link->width = strdup(origin->width);
    physical_link->speed = strdup(origin->speed);

    physical_link->edge = origin->edge;
    physical_link->other_way = origin->other_way;

    utarray_new(physical_link->partitions, &ut_ptr_icd);
    utarray_concat(physical_link->partitions, origin->partitions);

    physical_link->gbits = origin->gbits;

    physical_link->description = strdup(origin->description);

    return physical_link;
}

int netloc_physical_link_destruct(netloc_physical_link_t *link)
{
    free(link->width);
    free(link->description);
    free(link->speed);
    utarray_free(link->partitions);
    free(link);
    return NETLOC_SUCCESS;
}

char * netloc_link_pretty_print(netloc_physical_link_t* link)
{
    char * str = NULL;
    asprintf(&str, "%5llu (%s) [%23s] %d [<- %s / %s (%f) ->] (%s) [%23s] %d",
             link->id,
             netloc_node_type_encode(link->src->type),
             link->src->physical_id,
             link->ports[0],
             link->speed,
             link->width,
             link->gbits,
             netloc_node_type_encode(link->dest->type),
             link->dest->physical_id,
             link->ports[1]);
    return str;
}
