/*
 * Copyright © 2017 Inria.  All rights reserved.
 *
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 * See COPYING in top-level directory.
 *
 * $HEADER$
 */

#include <stdlib.h>

#include <netloc.h>
#include <private/netloc.h>
#include <netloc.h>

long int netloc_get_hopbyte(int num_ranks, double **comm, NETLOC_int *placement)
{
    int ret;
    // TODO check ret
    netloc_arch_t *arch = netloc_arch_construct();

    ret = netloc_arch_build(arch, 1);
    if (ret != NETLOC_SUCCESS)
        return ret;

    ret = netloc_arch_set_current_resources(arch);
    if (ret != NETLOC_SUCCESS)
        return ret;

    return arch_get_hopbyte(arch, num_ranks, comm, placement);
}

long int arch_get_hopbyte(netloc_arch_t *arch, int num_ranks, double **comm,
        NETLOC_int *placement)
{
    struct netloc_arch_tree_t *tree = arch->arch.global_tree;
    int size = tree->num_levels;
    NETLOC_int *degrees = tree->degrees;

    int placement_to_free = 0;
    if (!placement) {
        placement = (NETLOC_int *)malloc(sizeof(NETLOC_int[num_ranks]));
        placement_to_free = 1;
        for (int r = 0; r < num_ranks; r++) {
            placement[r] = arch->current_hosts[r];
        }
    }

    double hb = 0;
    for (int i = 0; i < num_ranks; i++) {
        int i_core_idx = placement[i];
        for (int j = 0; j < num_ranks; j++) {
            int j_core_idx = placement[j];
            int dist = tree_computeDistance(size, degrees,
                    i_core_idx, j_core_idx);
            hb += dist*comm[i][j];
        }
    }

    if (placement_to_free)
        free(placement);

    return (long int)hb;
}
