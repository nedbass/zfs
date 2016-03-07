/*
 * XXX missing license and copyright stuff
*/

#ifndef _SYS_MMP_H
#define	_SYS_MMP_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MMP_MAGIC		0xa11cea11		/* all-see-all */
#define	MMP_CLEAN_ID		0xc1e9b10c		/* clea(r/n)-block */

/*
 * MMP blocks may be written to disk by different processes.  Knowing which
 * process wrote a given block may help the sysadmin determine the order of
 * events, and which txg to roll back to, in the event of simultaneous imports
 * of a pool.
 */
typedef enum mmp_op {
	MO_TXG_SYNC,
	MO_INTERVAL_WRITE,
	MO_IMPORT_ATTEMPT,
} mmp_op_t;

struct mmp_phys {
	uint64_t  mmp_magic;		/* MMP_MAGIC if valid */
	uint64_t  mmp_pool_guid;	
	uint64_t  mmp_open_id;		/* ID associated with an import */
	uint64_t  mmp_seq;		/* MMP blocks written since open */
	uint32_t  mmp_interval;		/* Max time to next mmp write period between mmp write */
	uint32_t  mmp_delay;		/* Approx. delay at last update */
	char	  mmp_nodename[64];	/* Node which wrote this block */
	mmp_op_t  mmp_op;		/* Reason this block was written */
	uint64_t  mmp_first_txg;	/* First txg written by this node */
	/* zio_block_tail_t	mmp_zbt; */
};
typedef struct mmp_phys mmp_phys_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MMP_H */
