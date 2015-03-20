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

#if defined(_KERNEL) && defined(HAVE_DECLARE_EVENT_CLASS)

#undef TRACE_SYSTEM
#define	TRACE_SYSTEM zfs

#if !defined(_TRACE_ZAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define	_TRACE_ZAP_H

#include <linux/tracepoint.h>
#include <sys/types.h>

/*
 * Generic support for three argument tracepoints of the form:
 *
 * DTRACE_PROBE1(...,
 *     zap_t *, ...)
 */

#define	ZAP_TP_STRUCT_ENTRY					\
	__field(uint64_t,	zap_ds_object)			\
	__field(uint64_t,	zap_object)			\
	__field(boolean_t,	zap_ismicro)			\
	__field(int,		zap_normflags)			\
	__field(uint64_t,	zap_salt)			\
	__field(uint64_t,	zap_phys_block_type)		\
	__field(uint64_t,	zap_phys_magic)			\
	__field(uint64_t,	zap_phys_zt_blk)		\
	__field(uint64_t,	zap_phys_zt_numblks)		\
	__field(uint64_t,	zap_phys_zt_shift)		\
	__field(uint64_t,	zap_phys_zt_nextblk)		\
	__field(uint64_t,	zap_phys_zt_blks_copied)	\
	__field(uint64_t,	zap_phys_freeblk)		\
	__field(uint64_t,	zap_phys_num_leafs)		\
	__field(uint64_t,	zap_phys_num_entries)		\
	__field(uint64_t,	zap_phys_salt)			\
	__field(uint64_t,	zap_phys_normflags)		\
	__field(uint64_t,	zap_phys_flags)

#define	zap_f_phys		zap->zap_f.zap_phys
#define	zap_f_ptrtbl		zap_f_phys->zap_ptrtbl

#define	ZAP_TP_FAST_ASSIGN						\
	__entry->zap_ds_object	= zap->zap_objset->os_dsl_dataset ?	\
	    zap->zap_objset->os_dsl_dataset->ds_object : 0;		\
									\
	__entry->zap_object              = zap->zap_object;		\
	__entry->zap_ismicro             = zap->zap_ismicro;		\
	__entry->zap_normflags           = zap->zap_normflags;		\
	__entry->zap_salt                = zap->zap_salt;		\
	__entry->zap_phys_block_type     = zap_f_phys->zap_block_type;	\
	__entry->zap_phys_magic          = zap_f_phys->zap_magic;	\
	__entry->zap_phys_zt_blk         = zap_f_ptrtbl.zt_blk;		\
	__entry->zap_phys_zt_numblks     = zap_f_ptrtbl.zt_numblks;	\
	__entry->zap_phys_zt_shift       = zap_f_ptrtbl.zt_shift;	\
	__entry->zap_phys_zt_nextblk     = zap_f_ptrtbl.zt_nextblk;	\
	__entry->zap_phys_zt_blks_copied = zap_f_ptrtbl.zt_blks_copied;	\
	__entry->zap_phys_freeblk        = zap_f_phys->zap_freeblk;	\
	__entry->zap_phys_num_leafs      = zap_f_phys->zap_num_leafs;	\
	__entry->zap_phys_num_entries    = zap_f_phys->zap_num_entries;	\
	__entry->zap_phys_salt           = zap_f_phys->zap_salt;	\
	__entry->zap_phys_normflags      = zap_f_phys->zap_normflags;	\
	__entry->zap_phys_flags          = zap_f_phys->zap_flags;

#define	ZAP_TP_PRINTK_FMT						\
	"zap { os_object %llu object %llu ismicro %d normflags %d "	\
	"salt %llu phys_block_type %llu phys_magic %llx "		\
	"phys_zt_blk %llu phys_zt_numblks %llu phys_zt_shift %llu "	\
	"phys_zt_nextblk %llu phys_zt_blkscopied %llu "			\
	"phys_freeblk %llu phys_num_leafs %llu phys_num_entries %llu "	\
	"phys_salt %llu phys_normflags %llu phys_flags %llu }"

#define	ZAP_TP_PRINTK_ARGS						\
	__entry->zap_ds_object, __entry->zap_object,			\
	__entry->zap_ismicro, __entry->zap_normflags,			\
	__entry->zap_salt, __entry->zap_phys_block_type,		\
	__entry->zap_phys_magic, __entry->zap_phys_zt_blk,		\
	__entry->zap_phys_zt_numblks, __entry->zap_phys_zt_shift,	\
	__entry->zap_phys_zt_nextblk, __entry->zap_phys_zt_blks_copied,	\
	__entry->zap_phys_freeblk, __entry->zap_phys_num_leafs,		\
	__entry->zap_phys_num_entries, __entry->zap_phys_salt,		\
	__entry->zap_phys_normflags, __entry->zap_phys_flags

DECLARE_EVENT_CLASS(zfs_zap_class,
	TP_PROTO(zap_t *zap),
	TP_ARGS(zap),
	TP_STRUCT__entry(ZAP_TP_STRUCT_ENTRY),
	TP_fast_assign(ZAP_TP_FAST_ASSIGN),
	TP_printk(ZAP_TP_PRINTK_FMT, ZAP_TP_PRINTK_ARGS)
);

#define	DEFINE_ZAP_EVENT(name) \
DEFINE_EVENT(zfs_zap_class, name, \
	TP_PROTO(zap_t *zap), \
	TP_ARGS(zap))

#endif /* _TRACE_ZAP_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_PATH sys
#define	TRACE_INCLUDE_FILE trace_zap
#include <trace/define_trace.h>

#endif /* _KERNEL && HAVE_DECLARE_EVENT_CLASS */
