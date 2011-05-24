
/*
 * ZFS Event Daemon
 *
 * This userland component monitors /dev/zfs for various events that
 * may require intervention by a user to take corrective action or
 * an automated action, such replacing a failing device with a spare.
 *
 * TODO:
 *
 * Config file /etc/zfs/zeventd.conf
 *  major sections
 *   events device (default /dev/zfs)
 *   pool specific configs
 *   log destinations URI's good
 *    file
 *    syslog
 *     config logged info (i.e. vargs like printf)
 *    allow throttling of messages for log destinations
 *    ...
 *   actions (what to do in event of X)
 *    script(s) to launch
 *    launch N number of scripts
 *     serially or concurent?
 *   heuristics
 *    define/filter actions based on statistics
 *     RMS change in events
 * Action scripts dir /etc/zfs/zeventd.d
 *  support script library for parsing zpool event -v 
 *  
 *
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <syslog.h>
#include <libintl.h>

#include <sys/fs/zfs.h>
#include <sys/mount.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>

#include <libzfs.h>
#include "libzfs_impl.h"

libzfs_handle_t *g_zfs;
static int verbose = 0;

void usage(void)
{
	(void) printf( "usage:\n"
	    "\n"
	    "\tzeventd [-c configfile]\n"
	    "\t\t-v print verbose event data\n");
	exit(0);
}

static void
zpool_do_events_short(nvlist_t *nvl)
{
	char ctime_str[26], str[32], *ptr;
	int64_t *tv;
	uint_t n;

	verify(nvlist_lookup_int64_array(nvl, FM_EREPORT_TIME, &tv, &n) == 0);
	memset(str, ' ', 32);
	(void) ctime_r((const time_t *)&tv[0], ctime_str);
	(void) strncpy(str,    ctime_str+4,  6);             /* 'Jun 30'     */
	(void) strncpy(str+7,  ctime_str+20, 4);             /* '1993'       */
	(void) strncpy(str+12, ctime_str+11, 8);             /* '21:49:08'   */
	(void) sprintf(str+20, ".%09lld", (longlong_t)tv[1]);/* '.123456789' */
	(void) printf(gettext("%s "), str);

	verify(nvlist_lookup_string(nvl, FM_CLASS, &ptr) == 0);
	(void) printf(gettext("%s\n"), ptr);
}

static void
zpool_do_events_nvprint(nvlist_t *nvl, int depth)
{
	nvpair_t *nvp;

	for (nvp = nvlist_next_nvpair(nvl, NULL);
	    nvp != NULL; nvp = nvlist_next_nvpair(nvl, nvp)) {

		data_type_t type = nvpair_type(nvp);
		const char *name = nvpair_name(nvp);

		boolean_t b;
		uint8_t i8;
		uint16_t i16;
		uint32_t i32;
		uint64_t i64;
		char *str;
		nvlist_t *cnv;

		printf(gettext("%*s%s = "), depth, "", name);

		switch (type) {
		case DATA_TYPE_BOOLEAN:
			printf(gettext("%s"), "1");
			break;

		case DATA_TYPE_BOOLEAN_VALUE:
			(void) nvpair_value_boolean_value(nvp, &b);
			printf(gettext("%s"), b ? "1" : "0");
			break;

		case DATA_TYPE_BYTE:
			(void) nvpair_value_byte(nvp, &i8);
			printf(gettext("0x%x"), i8);
			break;

		case DATA_TYPE_INT8:
			(void) nvpair_value_int8(nvp, (void *)&i8);
			printf(gettext("0x%x"), i8);
			break;

		case DATA_TYPE_UINT8:
			(void) nvpair_value_uint8(nvp, &i8);
			printf(gettext("0x%x"), i8);
			break;

		case DATA_TYPE_INT16:
			(void) nvpair_value_int16(nvp, (void *)&i16);
			printf(gettext("0x%x"), i16);
			break;

		case DATA_TYPE_UINT16:
			(void) nvpair_value_uint16(nvp, &i16);
			printf(gettext("0x%x"), i16);
			break;

		case DATA_TYPE_INT32:
			(void) nvpair_value_int32(nvp, (void *)&i32);
			printf(gettext("0x%x"), i32);
			break;

		case DATA_TYPE_UINT32:
			(void) nvpair_value_uint32(nvp, &i32);
			printf(gettext("0x%x"), i32);
			break;

		case DATA_TYPE_INT64:
			(void) nvpair_value_int64(nvp, (void *)&i64);
			printf(gettext("0x%llx"), (u_longlong_t)i64);
			break;

		case DATA_TYPE_UINT64:
			(void) nvpair_value_uint64(nvp, &i64);
			printf(gettext("0x%llx"), (u_longlong_t)i64);
			break;

		case DATA_TYPE_HRTIME:
			(void) nvpair_value_hrtime(nvp, (void *)&i64);
			printf(gettext("0x%llx"), (u_longlong_t)i64);
			break;

		case DATA_TYPE_STRING:
			(void) nvpair_value_string(nvp, &str);
			printf(gettext("\"%s\""), str ? str : "<NULL>");
			break;

		case DATA_TYPE_NVLIST:
			printf(gettext("(embedded nvlist)\n"));
			(void) nvpair_value_nvlist(nvp, &cnv);
			zpool_do_events_nvprint(cnv, depth + 8);
			printf(gettext("%*s(end %s)"), depth, "", name);
			break;

		case DATA_TYPE_NVLIST_ARRAY: {
			nvlist_t **val;
			uint_t i, nelem;

			(void) nvpair_value_nvlist_array(nvp, &val, &nelem);
			printf(gettext("(%d embedded nvlists)\n"), nelem);
			for (i = 0; i < nelem; i++) {
				printf(gettext("%*s%s[%d] = %s\n"),
				       depth, "", name, i, "(embedded nvlist)");
				zpool_do_events_nvprint(val[i], depth + 8);
				printf(gettext("%*s(end %s[%i])\n"),
				       depth, "", name, i);
			}
			printf(gettext("%*s(end %s)\n"), depth, "", name);
			}
			break;

		case DATA_TYPE_INT8_ARRAY: {
			int8_t *val;
			uint_t i, nelem;

			(void) nvpair_value_int8_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%x "), val[i]);

			break;
			}

		case DATA_TYPE_UINT8_ARRAY: {
			uint8_t *val;
			uint_t i, nelem;

			(void) nvpair_value_uint8_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%x "), val[i]);

			break;
			}

		case DATA_TYPE_INT16_ARRAY: {
			int16_t *val;
			uint_t i, nelem;

			(void) nvpair_value_int16_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%x "), val[i]);

			break;
			}

		case DATA_TYPE_UINT16_ARRAY: {
			uint16_t *val;
			uint_t i, nelem;

			(void) nvpair_value_uint16_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%x "), val[i]);

			break;
			}

		case DATA_TYPE_INT32_ARRAY: {
			int32_t *val;
			uint_t i, nelem;

			(void) nvpair_value_int32_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%x "), val[i]);

			break;
			}

		case DATA_TYPE_UINT32_ARRAY: {
			uint32_t *val;
			uint_t i, nelem;

			(void) nvpair_value_uint32_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%x "), val[i]);

			break;
			}

		case DATA_TYPE_INT64_ARRAY: {
			int64_t *val;
			uint_t i, nelem;

			(void) nvpair_value_int64_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%llx "), (u_longlong_t)val[i]);

			break;
			}

		case DATA_TYPE_UINT64_ARRAY: {
			uint64_t *val;
			uint_t i, nelem;

			(void) nvpair_value_uint64_array(nvp, &val, &nelem);
			for (i = 0; i < nelem; i++)
				printf(gettext("0x%llx "), (u_longlong_t)val[i]);

			break;
			}

		case DATA_TYPE_STRING_ARRAY:
		case DATA_TYPE_BOOLEAN_ARRAY:
		case DATA_TYPE_BYTE_ARRAY:
		case DATA_TYPE_DOUBLE:
		case DATA_TYPE_UNKNOWN:
			printf(gettext("<unknown>"));
			break;
		}

		printf(gettext("\n"));
	}
}

int zevent_daemon(void)
{
	nvlist_t *nvl = NULL;
	int dropped = 0;
	int block = 1;
	int ret;
	int cleanup_fd;

	if ((g_zfs = libzfs_init()) == NULL)
		return (1);

	cleanup_fd = open(ZFS_DEV, O_RDWR);
	VERIFY(cleanup_fd >= 0);

	while (1) {
		ret = zpool_events_next(g_zfs, &nvl, &dropped, block,
		    cleanup_fd);
		if (nvl != NULL) {
			if (verbose)
				zpool_do_events_short(nvl);
			else
				zpool_do_events_nvprint(nvl, 8);
			nvlist_free(nvl);
		}
	}

	VERIFY(0 == close(cleanup_fd));
}

int main(int argc, char **argv)
{
	int c;
	int ret = 0;
	int verbose;
	char *configf;

	while ((c = getopt(argc, argv, "c:hv")) != -1 ) {
		switch (c) {
		case 'c':
			configf = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage();
			break;
		}
	}

	openlog(argv[0], LOG_CONS|LOG_PID, LOG_DAEMON);

	if (configf == NULL)
		configf = "/etc/zfs/zeventd.conf";

	ret = zevent_daemon();

	return (ret);
}
