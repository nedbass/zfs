#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_scrub/zpool_scrub.cfg

#
# DESCRIPTION:
#	Verify scrub -s works correctly.
#
# STRATEGY:
#	1. Create pool and fill with hundreds data.
#	2. zpool scrub the pool
#	3. Verify zpool scrub -s succeed when the system is scrubbing.
#
# NOTES:
#	A 1 second delay is added to 10% of zio's in order to ensure that
#	the scrub does not complete before it has a chance to be cancelled.
#	This can occur when testing with small pools or very fast hardware.
#

verify_runnable "global"

log_assert "Verify scrub -s works correctly."

log_must $ZINJECT -d $DISK1 -f10 -D1 $TESTPOOL
log_must $ZPOOL scrub $TESTPOOL
log_must $ZPOOL scrub -s $TESTPOOL
log_must is_pool_scrub_stopped $TESTPOOL

log_must $ZINJECT -c all
log_pass "Verify scrub -s works correctly."
