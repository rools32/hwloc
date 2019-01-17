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

#define _GNU_SOURCE	   /* See feature_test_macros(7) */
#include <stdio.h>

#include <netloc.h>
#include <private/netloc.h>

#include "tree.h"

int netloc_arch_build(netloc_machine_t *machine)
{
    // XXX TODO choose right function depending on network
    partition_topology_to_tleaf(machine);
    //partition_topology_to_deco(machine);

    return NETLOC_SUCCESS;
}
