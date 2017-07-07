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

#include <netloc.h>
#include <private/netloc.h>

int tree_computeDistance(int size, NETLOC_int *tree, int idx1, int idx2)
{
    if (idx1 == idx2)
        return 0;

    return tree_computeDistance(size-1, tree,
            idx1/tree[size-1], idx2/tree[size-1])+1;
}


