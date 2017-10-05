/* Copyright (C) 2011,2016-2017 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted for any purpose (including commercial purposes)
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions, and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions, and the following disclaimer in the
 *    documentation and/or materials provided with the distribution.
 *
 * 3. In addition, redistributions of modified forms of the source or binary
 *    code must carry prominent notices stating that the original code was
 *    changed and the date of the change.
 *
 *  4. All publications or advertising materials mentioning features or use of
 *     this software are asked, but not required, to acknowledge that it was
 *     developed by Intel Corporation and credit the contributors.
 *
 * 5. Neither the name of Intel Corporation, nor the name of any Contributor
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * This file is part of gurt, it implements the gurt bin heap functions.
 */

#include <pthread.h>
#include <gurt/common.h>
#include <gurt/heap.h>

static void
dbh_lock_init(struct d_binheap *h)
{
	if (h->d_bh_feats & DBH_FT_NOLOCK)
		return;

	if (h->d_bh_feats & DBH_FT_RWLOCK)
		pthread_rwlock_init(&h->d_bh_rwlock, NULL);
	else
		pthread_mutex_init(&h->d_bh_mutex, NULL);
}

static void
dbh_lock_fini(struct d_binheap *h)
{
	if (h->d_bh_feats & DBH_FT_NOLOCK)
		return;

	if (h->d_bh_feats & DBH_FT_RWLOCK)
		pthread_rwlock_destroy(&h->d_bh_rwlock);
	else
		pthread_mutex_destroy(&h->d_bh_mutex);
}

/** lock the bin heap */
static void
dbh_lock(struct d_binheap *h, bool read_only)
{
	if (h->d_bh_feats & DBH_FT_NOLOCK)
		return;

	if (h->d_bh_feats & DBH_FT_RWLOCK) {
		if (read_only)
			pthread_rwlock_rdlock(&h->d_bh_rwlock);
		else
			pthread_rwlock_wrlock(&h->d_bh_rwlock);
	} else {
		pthread_mutex_lock(&h->d_bh_mutex);
	}
}

/** unlock the bin heap */
static void
dbh_unlock(struct d_binheap *h, bool read_only)
{
	if (h->d_bh_feats & DBH_FT_NOLOCK)
		return;

	if (h->d_bh_feats & DBH_FT_RWLOCK)
		pthread_rwlock_unlock(&h->d_bh_rwlock);
	else
		pthread_mutex_unlock(&h->d_bh_mutex);
}

/** Grows the capacity of a binary heap */
static int
d_binheap_grow(struct d_binheap *h)
{
	struct d_binheap_node		***frag1 = NULL;
	struct d_binheap_node		 **frag2;
	uint32_t			   hwm;

	D_ASSERT(h != NULL);
	hwm = h->d_bh_hwm;

	/* need a whole new chunk of pointers */
	D_ASSERT((h->d_bh_hwm & DBH_MASK) == 0);

	if (hwm == 0) {
		/* first use of single indirect */
		D_ALLOC(h->d_bh_nodes1, DBH_NOB);
		if (h->d_bh_nodes1 == NULL)
			return -DER_NOMEM;

		goto out;
	}

	hwm -= DBH_SIZE;
	if (hwm < DBH_SIZE * DBH_SIZE) {
		/* not filled double indirect */
		D_ALLOC(frag2, DBH_NOB);
		if (frag2 == NULL)
			return -DER_NOMEM;

		if (hwm == 0) {
			/* first use of double indirect */
			D_ALLOC(h->d_bh_nodes2, DBH_NOB);
			if (h->d_bh_nodes2 == NULL) {
				D_FREE(frag2, DBH_NOB);
				return -DER_NOMEM;
			}
		}

		h->d_bh_nodes2[hwm >> DBH_SHIFT] = frag2;
		goto out;
	}

	hwm -= DBH_SIZE * DBH_SIZE;
#if (DBH_SHIFT * 3 < 32)
	if (hwm >= DBH_SIZE * DBH_SIZE * DBH_SIZE) {
		/* filled triple indirect */
		return -DER_NOMEM;
	}
#endif
	D_ALLOC(frag2, DBH_NOB);
	if (frag2 == NULL)
		return -DER_NOMEM;

	if (((hwm >> DBH_SHIFT) & DBH_MASK) == 0) {
		/* first use of this 2nd level index */
		D_ALLOC(frag1, DBH_NOB);
		if (frag1 == NULL) {
			D_FREE(frag2, DBH_NOB);
			return -DER_NOMEM;
		}
	}

	if (hwm == 0) {
		/* first use of triple indirect */
		D_ALLOC(h->d_bh_nodes3, DBH_NOB);
		if (h->d_bh_nodes3 == NULL) {
			D_FREE(frag2, DBH_NOB);
			D_FREE(frag1, DBH_NOB);
			return -DER_NOMEM;
		}
	}

	if (frag1 != NULL) {
		D_ASSERT(h->d_bh_nodes3[hwm >> (2 * DBH_SHIFT)] == NULL);
		h->d_bh_nodes3[hwm >> (2 * DBH_SHIFT)] = frag1;
	} else {
		frag1 = h->d_bh_nodes3[hwm >> (2 * DBH_SHIFT)];
		D_ASSERT(frag1 != NULL);
	}

	frag1[(hwm >> DBH_SHIFT) & DBH_MASK] = frag2;

 out:
	h->d_bh_hwm += DBH_SIZE;
	return 0;
}

int
d_binheap_create_inplace(uint32_t feats, uint32_t count, void *priv,
			 struct d_binheap_ops *ops, struct d_binheap *h)
{
	int	rc;

	if (ops == NULL || ops->hop_compare == NULL) {
		D_ERROR("invalid parameter, should pass in valid ops table.\n");
		return -DER_INVAL;
	}
	if (h == NULL) {
		D_ERROR("invalid parameter of NULL heap pointer.\n");
		return -DER_INVAL;
	}

	h->d_bh_ops	  = ops;
	h->d_bh_nodes_cnt  = 0;
	h->d_bh_hwm	  = 0;
	h->d_bh_priv	  = priv;
	h->d_bh_feats	  = feats;

	while (h->d_bh_hwm < count) { /* preallocate */
	rc = d_binheap_grow(h);
		if (rc != 0) {
			D_ERROR("d_binheap_grow failed, rc: %d.\n", rc);
			d_binheap_destroy_inplace(h);
			return rc;
		}
	}

	dbh_lock_init(h);

	return 0;
}

int
d_binheap_create(uint32_t feats, uint32_t count, void *priv,
		 struct d_binheap_ops *ops, struct d_binheap **h)
{
	struct d_binheap	*bh_created;
	int			 rc;

	if (ops == NULL || ops->hop_compare == NULL) {
		D_ERROR("invalid parameter, should pass in valid ops table.\n");
		return -DER_INVAL;
	}
	if (h == NULL) {
		D_ERROR("invalid parameter of NULL heap 2nd level pointer.\n");
		return -DER_INVAL;
	}

	D_ALLOC_PTR(bh_created);
	if (bh_created == NULL)
		return -DER_NOMEM;

	rc = d_binheap_create_inplace(feats, count, priv, ops, bh_created);
	if (rc != 0) {
		D_ERROR("d_binheap_create_inplace failed, rc: %d.\n", rc);
		D_FREE_PTR(bh_created);
		return rc;
	}

	*h = bh_created;

	return rc;
}

void
d_binheap_destroy_inplace(struct d_binheap *h)
{
	uint32_t	idx0, idx1, n;

	if (h == NULL) {
		D_ERROR("ignore invalid parameter of NULL heap.\n");
		return;
	}

	n = h->d_bh_hwm;

	if (n > 0) {
		D_FREE(h->d_bh_nodes1, DBH_NOB);
		n -= DBH_SIZE;
	}

	if (n > 0) {
		for (idx0 = 0; idx0 < DBH_SIZE && n > 0; idx0++) {
			D_FREE(h->d_bh_nodes2[idx0], DBH_NOB);
			n -= DBH_SIZE;
		}

		D_FREE(h->d_bh_nodes2, DBH_NOB);
	}

	if (n > 0) {
		for (idx0 = 0; idx0 < DBH_SIZE && n > 0; idx0++) {

			for (idx1 = 0; idx1 < DBH_SIZE && n > 0; idx1++) {
				D_FREE(h->d_bh_nodes3[idx0][idx1], DBH_NOB);
				n -= DBH_SIZE;
			}

			D_FREE(h->d_bh_nodes3[idx0], DBH_NOB);
		}

		D_FREE(h->d_bh_nodes3, DBH_NOB);
	}

	dbh_lock_fini(h);

	memset(h, 0, sizeof(*h));
}

void
d_binheap_destroy(struct d_binheap *h)
{
	if (h == NULL) {
		D_ERROR("ignore invalid parameter of NULL heap.\n");
		return;
	}

	d_binheap_destroy_inplace(h);
	D_FREE_PTR(h);
}

/**
 * Obtains a double pointer to a heap node, given its index into the binary
 * tree.
 *
 * \param h [in]	The binary heap instance
 * \param idx [in]	The requested node's index
 *
 * \return		valid-pointer A double pointer to a heap pointer entry
 */
static struct d_binheap_node **
d_binheap_pointer(struct d_binheap *h, uint32_t idx)
{
	if (idx < DBH_SIZE)
		return &(h->d_bh_nodes1[idx]);

	idx -= DBH_SIZE;
	if (idx < DBH_SIZE * DBH_SIZE)
		return &(h->d_bh_nodes2[idx >> DBH_SHIFT][idx & DBH_MASK]);

	idx -= DBH_SIZE * DBH_SIZE;
	return &(h->d_bh_nodes3[idx >> (2 * DBH_SHIFT)]
				 [(idx >> DBH_SHIFT) & DBH_MASK]
				 [idx & DBH_MASK]);
}

static struct d_binheap_node *
d_binheap_find_locked(struct d_binheap *h, uint32_t idx)
{
	struct d_binheap_node **node;

	if (h == NULL) {
		D_ERROR("ignore NULL heap.\n");
		return NULL;
	}

	if (idx >= h->d_bh_nodes_cnt)
		return NULL;

	node = d_binheap_pointer(h, idx);

	return *node;
}

struct d_binheap_node *
d_binheap_find(struct d_binheap *h, uint32_t idx)
{
	struct d_binheap_node *node;

	dbh_lock(h, true /* read-only */);
	node = d_binheap_find_locked(h, idx);
	dbh_unlock(h, true /* read-only */);

	return node;
}

/**
 * Moves a node upwards, towards the root of the binary tree.
 *
 * \param h [in]	The heap
 * \param e [in]	The node
 *
 * \return		1 the position of \a e in the tree was changed at least
 *			once;
 *			0 the position of \a e in the tree was not changed
 */
static int
d_binheap_bubble(struct d_binheap *h, struct d_binheap_node *e)
{
	struct d_binheap_node		**cur_ptr;
	struct d_binheap_node		**parent_ptr;
	uint32_t			  cur_idx;
	uint32_t			  parent_idx;
	int				  did_sth = 0;

	D_ASSERT(h != NULL && e != NULL);
	cur_idx = e->chn_idx;
	cur_ptr = d_binheap_pointer(h, cur_idx);
	D_ASSERT(*cur_ptr == e);

	while (cur_idx > 0) {
		parent_idx = (cur_idx - 1) >> 1;

		parent_ptr = d_binheap_pointer(h, parent_idx);
		D_ASSERT((*parent_ptr)->chn_idx == parent_idx);

		if (h->d_bh_ops->hop_compare(*parent_ptr, e))
			break;

		(*parent_ptr)->chn_idx = cur_idx;
		*cur_ptr = *parent_ptr;
		cur_ptr = parent_ptr;
		cur_idx = parent_idx;
		did_sth = 1;
	}

	e->chn_idx = cur_idx;
	*cur_ptr = e;

	return did_sth;
}

/**
 * Moves a node downwards, towards the last level of the binary tree.
 *
 * \param h [IN]	The heap
 * \param e [IN]	The node
 *
 * \return		1 The position of \a e in the tree was changed at least
 *			once;
 *			0 The position of \a e in the tree was not changed.
 */
static int
d_binheap_sink(struct d_binheap *h, struct d_binheap_node *e)
{
	struct d_binheap_node		**child_ptr;
	struct d_binheap_node		 *child;
	struct d_binheap_node		**child2_ptr;
	struct d_binheap_node		  *child2;
	struct d_binheap_node		**cur_ptr;
	uint32_t			  child2_idx;
	uint32_t			  child_idx;
	uint32_t			  cur_idx;
	uint32_t			  n;
	int				  did_sth = 0;

	D_ASSERT(h != NULL && e != NULL);

	n = h->d_bh_nodes_cnt;
	cur_idx = e->chn_idx;
	cur_ptr = d_binheap_pointer(h, cur_idx);
	D_ASSERT(*cur_ptr == e);

	while (cur_idx < n) {
		child_idx = (cur_idx << 1) + 1;
		if (child_idx >= n)
			break;

		child_ptr = d_binheap_pointer(h, child_idx);
		child = *child_ptr;

		child2_idx = child_idx + 1;
		if (child2_idx < n) {
			child2_ptr = d_binheap_pointer(h, child2_idx);
			child2 = *child2_ptr;

			if (h->d_bh_ops->hop_compare(child2, child)) {
				child_idx = child2_idx;
				child_ptr = child2_ptr;
				child = child2;
			}
		}

		D_ASSERT(child->chn_idx == child_idx);

		if (h->d_bh_ops->hop_compare(e, child))
			break;

		child->chn_idx = cur_idx;
		*cur_ptr = child;
		cur_ptr = child_ptr;
		cur_idx = child_idx;
		did_sth = 1;
	}

	e->chn_idx = cur_idx;
	*cur_ptr = e;

	return did_sth;
}

int
d_binheap_insert(struct d_binheap *h, struct d_binheap_node *e)
{
	struct d_binheap_node		**new_ptr;
	uint32_t			  new_idx;
	int				  rc;

	if (h == NULL || e == NULL) {
		D_ERROR("invalid parameter of NULL h or e.\n");
		return -DER_INVAL;
	}

	dbh_lock(h, false /* read-only */);

	new_idx = h->d_bh_nodes_cnt;
	D_ASSERT(new_idx <= h->d_bh_hwm);
	if (new_idx == h->d_bh_hwm) {
		rc = d_binheap_grow(h);
		if (rc != 0) {
			D_ERROR("d_binheap_grow failed, rc: %d.\n", rc);
			dbh_unlock(h, false /* read-only */);
			return rc;
		}
	}

	if (h->d_bh_ops->hop_enter) {
		rc = h->d_bh_ops->hop_enter(h, e);
		if (rc != 0) {
			D_ERROR("d_bh_ops->hop_enter failed, rc: %d.\n", rc);
			dbh_unlock(h, false /* read-only */);
			return rc;
		}
	}

	e->chn_idx = new_idx;
	new_ptr = d_binheap_pointer(h, new_idx);
	h->d_bh_nodes_cnt++;
	*new_ptr = e;

	d_binheap_bubble(h, e);

	dbh_unlock(h, false /* read-only */);

	return 0;
}

static void
d_binheap_remove_locked(struct d_binheap *h, struct d_binheap_node *e)
{
	struct d_binheap_node		**cur_ptr;
	struct d_binheap_node		 *last;
	uint32_t			  cur_idx;
	uint32_t			  n;

	if (h == NULL || e == NULL) {
		D_ERROR("invalid parameter of NULL h or e.\n");
		return;
	}

	n = h->d_bh_nodes_cnt;
	cur_idx = e->chn_idx;

	D_ASSERT(cur_idx != DBH_POISON);
	D_ASSERT(cur_idx < n);

	cur_ptr = d_binheap_pointer(h, cur_idx);
	D_ASSERT(*cur_ptr == e);

	n--;
	last = *d_binheap_pointer(h, n);
	h->d_bh_nodes_cnt = n;
	if (last == e)
		goto out;

	last->chn_idx = cur_idx;
	*cur_ptr = last;
	if (!d_binheap_bubble(h, *cur_ptr))
		d_binheap_sink(h, *cur_ptr);

out:
	e->chn_idx = DBH_POISON;
	if (h->d_bh_ops->hop_exit)
		h->d_bh_ops->hop_exit(h, e);
}

void
d_binheap_remove(struct d_binheap *h, struct d_binheap_node *e)
{
	dbh_lock(h, false /* read-only */);
	d_binheap_remove_locked(h, e);
	dbh_unlock(h, false /* read-only */);
}

struct d_binheap_node *
d_binheap_remove_root(struct d_binheap *h)
{
	struct d_binheap_node *e;

	if (h == NULL) {
		D_ERROR("ignore NULL heap.\n");
		return NULL;
	}

	dbh_lock(h, false /* read-only */);

	e = d_binheap_find_locked(h, 0);
	if (e != NULL)
		d_binheap_remove_locked(h, e);

	dbh_unlock(h, false /* read-only */);

	return e;
}