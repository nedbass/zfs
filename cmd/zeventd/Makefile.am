include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zeventd

zeventd_SOURCES = \
	$(top_srcdir)/cmd/zeventd/zeventd.c

zeventd_LDADD = \
	$(top_builddir)/lib/libspl/libspl.la \
	$(top_builddir)/lib/libavl/libavl.la \
	$(top_builddir)/lib/libefi/libefi.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libunicode/libunicode.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la

zeventd_LDFLAGS = -pthread -lm $(ZLIB) -lrt -ldl $(LIBUUID) $(LIBBLKID)
