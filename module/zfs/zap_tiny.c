/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, 2014 by Delphix. All rights reserved.
 * Copyright (c) 2014 Spectra Logic Corporation, All rights reserved.
 */

#include <sys/zio.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/zfs_context.h>
#include <sys/zap.h>
#include <sys/refcount.h>
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>
#include <sys/avl.h>
#include <sys/arc.h>
#include <sys/dmu_objset.h>

#ifdef _KERNEL
#include <sys/sunddi.h>
#endif

int
tze_compare(const void *arg1, const void *arg2)
{
	const tzap_ent_t *tze1 = arg1;
	const tzap_ent_t *tze2 = arg2;

	if (tze1->tze_hash > tze2->tze_hash)
		return (+1);
	if (tze1->tze_hash < tze2->tze_hash)
		return (-1);
	if (tze1->tze_cd > tze2->tze_cd)
		return (+1);
	if (tze1->tze_cd < tze2->tze_cd)
		return (-1);
	return (0);
}

void
tze_insert(zap_t *zap, int chunkid, uint64_t hash)
{
	tzap_ent_t *tze;

	ASSERT(zap->zap_istiny);
	ASSERT(RW_WRITE_HELD(&zap->zap_rwlock));

	tze = kmem_alloc(sizeof (tzap_ent_t), KM_SLEEP);
	tze->tze_chunkid = chunkid;
	tze->tze_hash = hash;
	tze->tze_cd = TZE_PHYS(zap, tze)->tze_cd;
	ASSERT(TZE_PHYS(zap, tze)->tze_name[0] != 0);
	avl_add(&zap->zap_m.zap_avl, tze);
}

tzap_ent_t *
tze_find(zap_name_t *zn)
{
	tzap_ent_t tze_tofind;
	tzap_ent_t *tze;
	avl_index_t idx;
	avl_tree_t *avl = &zn->zn_zap->zap_m.zap_avl;

	ASSERT(zn->zn_zap->zap_istiny);
	ASSERT(RW_LOCK_HELD(&zn->zn_zap->zap_rwlock));

	tze_tofind.tze_hash = zn->zn_hash;
	tze_tofind.tze_cd = 0;

again:
	tze = avl_find(avl, &tze_tofind, &idx);
	if (tze == NULL)
		tze = avl_nearest(avl, idx, AVL_AFTER);
	for (; tze && tze->tze_hash == zn->zn_hash; tze = AVL_NEXT(avl, tze)) {
		ASSERT3U(tze->tze_cd, ==, TZE_PHYS(zn->zn_zap, tze)->tze_cd);
		if (zap_match(zn, TZE_PHYS(zn->zn_zap, tze)->tze_name))
			return (tze);
	}
	if (zn->zn_matchtype == MT_BEST) {
		zn->zn_matchtype = MT_FIRST;
		goto again;
	}
	return (NULL);
}

uint32_t
tze_find_unused_cd(zap_t *zap, uint64_t hash)
{
	tzap_ent_t tze_tofind;
	tzap_ent_t *tze;
	avl_index_t idx;
	avl_tree_t *avl = &zap->zap_m.zap_avl;
	uint32_t cd;

	ASSERT(zap->zap_istiny);
	ASSERT(RW_LOCK_HELD(&zap->zap_rwlock));

	tze_tofind.tze_hash = hash;
	tze_tofind.tze_cd = 0;

	cd = 0;
	for (tze = avl_find(avl, &tze_tofind, &idx);
	    tze && tze->tze_hash == hash; tze = AVL_NEXT(avl, tze)) {
		if (tze->tze_cd != cd)
			break;
		cd++;
	}

	return (cd);
}

void
tze_remove(zap_t *zap, tzap_ent_t *tze)
{
	ASSERT(zap->zap_istiny);
	ASSERT(RW_WRITE_HELD(&zap->zap_rwlock));

	avl_remove(&zap->zap_m.zap_avl, tze);
	kmem_free(tze, sizeof (tzap_ent_t));
}

void
tze_destroy(zap_t *zap)
{
	tzap_ent_t *tze;
	void *avlcookie = NULL;

	while ((tze = avl_destroy_nodes(&zap->zap_m.zap_avl, &avlcookie)))
		kmem_free(tze, sizeof (tzap_ent_t));
	avl_destroy(&zap->zap_m.zap_avl);
}

int
tzap_upgrade(zap_t **zapp, dmu_tx_t *tx, zap_flags_t flags)
{
	tzap_phys_t *tzp;
	int i, sz, nchunks;
	int err = 0;
	zap_t *zap = *zapp;

	ASSERT(RW_WRITE_HELD(&zap->zap_rwlock));

	sz = zap->zap_dbuf->db_size;
	tzp = zio_buf_alloc(sz);
	bcopy(zap->zap_dbuf->db_data, tzp, sz);
	nchunks = zap->zap_m.zap_num_chunks;

	if (!flags) {
		err = dmu_object_set_blocksize(zap->zap_objset, zap->zap_object,
		    1ULL << fzap_default_block_shift, 0, tx);
		if (err) {
			zio_buf_free(tzp, sz);
			return (err);
		}
	}

	dprintf("upgrading obj=%llu with %u chunks\n",
	    zap->zap_object, nchunks);
	/* XXX destroy the avl later, so we can use the stored hash value */
	tze_destroy(zap);

	fzap_upgrade(zap, tx, flags);

	for (i = 0; i < nchunks; i++) {
		tzap_ent_phys_t *tze = &tzp->tz_chunk[i];
		zap_name_t *zn;
		if (tze->tze_name[0] == 0)
			continue;
		dprintf("adding %s=%llu\n",
		    tze->tze_name, tze->tze_value);
		zn = zap_name_alloc(zap, tze->tze_name, MT_EXACT);
		err = fzap_add_cd(zn, 8, tze->tze_num_ints, &tze->tze_value,
		    tze->tze_cd, tx);
		zap = zn->zn_zap;	/* fzap_add_cd() may change zap */
		zap_name_free(zn);
		if (err)
			break;
	}
	zio_buf_free(tzp, sz);
	*zapp = zap;
	return (err);
}

void
tzap_addent(zap_name_t *zn, uint64_t num_integers, const void *val)
{
	int i;
	zap_t *zap = zn->zn_zap;
	int start = zap->zap_m.zap_alloc_next;
	const uint64_t *intval = val;
	uint32_t cd;

	ASSERT(RW_WRITE_HELD(&zap->zap_rwlock));
	ASSERT3U(num_integers, <=, 8);

#ifdef ZFS_DEBUG
	for (i = 0; i < zap->zap_m.zap_num_chunks; i++) {
		ASSERTV(tzap_ent_phys_t *tze);
		ASSERT(tze = &zap_t_phys(zap)->tz_chunk[i]);
		ASSERT(strcmp(zn->zn_key_orig, tze->tze_name) != 0);
	}
#endif

	cd = tze_find_unused_cd(zap, zn->zn_hash);
	/* given the limited size of the microzap, this can't happen */
	ASSERT(cd < zap_maxcd(zap));

again:
	for (i = start; i < zap->zap_m.zap_num_chunks; i++) {
		tzap_ent_phys_t *tze = &zap_t_phys(zap)->tz_chunk[i];
		if (tze->tze_name[0] == 0) {
			int j;
			for (j=0; j < num_integers; j++)
				tze->tze_value[j] = *(intval + j);
			tze->tze_cd = cd;
			tze->tze_num_ints = num_integers;
			(void) strcpy(tze->tze_name, zn->zn_key_orig);
			zap->zap_m.zap_num_entries++;
			zap->zap_m.zap_alloc_next = i+1;
			if (zap->zap_m.zap_alloc_next ==
			    zap->zap_m.zap_num_chunks)
				zap->zap_m.zap_alloc_next = 0;
			tze_insert(zap, i, zn->zn_hash);
			return;
		}
	}
	if (start != 0) {
		start = 0;
		goto again;
	}
	cmn_err(CE_PANIC, "out of entries!");
}

/*
 * zn may be NULL; if not specified, it will be computed if needed.
 * See also the comment above zap_entry_normalization_conflict().
 */
boolean_t
tzap_normalization_conflict(zap_t *zap, zap_name_t *zn, tzap_ent_t *tze)
{
	tzap_ent_t *other;
	int direction = AVL_BEFORE;
	boolean_t allocdzn = B_FALSE;

	if (zap->zap_normflags == 0)
		return (B_FALSE);

again:
	for (other = avl_walk(&zap->zap_m.zap_avl, tze, direction);
	    other && other->tze_hash == tze->tze_hash;
	    other = avl_walk(&zap->zap_m.zap_avl, other, direction)) {

		if (zn == NULL) {
			zn = zap_name_alloc(zap, TZE_PHYS(zap, tze)->tze_name,
			    MT_FIRST);
			allocdzn = B_TRUE;
		}
		if (zap_match(zn, TZE_PHYS(zap, other)->tze_name)) {
			if (allocdzn)
				zap_name_free(zn);
			return (B_TRUE);
		}
	}

	if (direction == AVL_BEFORE) {
		direction = AVL_AFTER;
		goto again;
	}

	if (allocdzn)
		zap_name_free(zn);
	return (B_FALSE);
}
