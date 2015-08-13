###############################################################################
#
# Author: John Ogness
#
# This file has been put into the public domain.
# You can do whatever you want with this file.
#
###############################################################################

AC_PREREQ(2.5)
AC_INIT(minicoredumper, 1.0.0, john.ogness@linutronix.de)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE

AM_CONFIG_HEADER(config.h)

AC_SUBST(VERSION)

ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

AC_CANONICAL_HOST
AC_CANONICAL_BUILD
AC_LANG([C])

dnl Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_C_INLINE
AC_PROG_CXX

LT_INIT

AC_DEFINE(_GNU_SOURCE, , GNU SOURCE)

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([elf.h],,[AC_MSG_ERROR([elf.h missing!])])
AC_CHECK_HEADERS([gelf.h],,[AC_MSG_ERROR([gelf.h missing!])])
AC_CHECK_HEADERS([fcntl.h],,[AC_MSG_ERROR([fcntl.h missing!])])
AC_CHECK_HEADERS([limits.h],,[AC_MSG_ERROR([limits.h missing!])])
AC_CHECK_HEADERS([stddef.h],,[AC_MSG_ERROR([stddef.h missing!])])
AC_CHECK_HEADERS([syslog.h],,[AC_MSG_ERROR([syslog.h missing!])])
AC_CHECK_HEADERS([argp.h],,[AC_MSG_ERROR([argp.h missing!])])
AC_CHECK_HEADER_STDBOOL

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

dnl Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([mkdir])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strndup])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([atexit])
AC_CHECK_FUNCS([strrchr])
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_STRTOD

dnl default-enabled dbus feature
AC_ARG_WITH([dbus],
	    [AS_HELP_STRING([--with-dbus],
	    [link with D-Bus to use notification features @<:@default=autodetect@:>@])],
	    [],
	    [with_dbus=check])
AS_CASE(["$with_dbus"],
	[yes], [PKG_CHECK_MODULES([dbus], [dbus-1 dbus-glib-1 uuid], [HAVE_DBUS=1])],
	[no], [HAVE_DBUS=0],
	[PKG_CHECK_MODULES([dbus], [dbus-1 dbus-glib-1 uuid], [HAVE_DBUS=1], [HAVE_DBUS=0])])
AM_CONDITIONAL([USE_DBUS], [test "x$with_dbus" = "xyes" -o "$HAVE_DBUS" -eq 1])

AC_ARG_WITH([coreinject],
	    [AS_HELP_STRING([--without-coreinject],
	    [build coreinject tool @<:@default=with@:>@])])
AS_CASE(["$with_coreinject"],
	[yes], [WANT_COREINJECT=1],
	[no], [WANT_COREINJECT=0],
	[WANT_COREINJECT=1])
AM_CONDITIONAL([COND_COREINJECT], [test "$WANT_COREINJECT" -eq 1])

AC_ARG_WITH([minicoredumper],
	    [AS_HELP_STRING([--without-minicoredumper],
	    [build minicoredumper tool @<:@default=with@:>@])])
AS_CASE(["$with_minicoredumper"],
	[yes], [WANT_MINICOREDUMPER=1],
	[no], [WANT_MINICOREDUMPER=0],
	[WANT_MINICOREDUMPER=1])
AM_CONDITIONAL([COND_MINICOREDUMPER], [test "$WANT_MINICOREDUMPER" -eq 1])

AC_ARG_WITH([minicoredumper_dbusd],
	    [AS_HELP_STRING([--without-minicoredumper_dbusd],
	    [build minicoredumper_dbusd daemon @<:@default=with@:>@])])
AS_CASE(["$with_minicoredumper_dbusd"],
	[yes], [WANT_MINICOREDUMPER_DBUSD=1],
	[no], [WANT_MINICOREDUMPER_DBUSD=0],
	[WANT_MINICOREDUMPER_DBUSD=1])
AM_CONDITIONAL([COND_MINICOREDUMPER_DBUSD], [test "$WANT_MINICOREDUMPER_DBUSD" -eq 1 -a "x$with_dbus" = "xyes" -o "$HAVE_DBUS" -eq 1])

AC_ARG_WITH([minicoredumper_trigger],
	    [AS_HELP_STRING([--without-minicoredumper_trigger],
	    [build minicoredumper_trigger tool @<:@default=with@:>@])])
AS_CASE(["$with_minicoredumper_trigger"],
	[yes], [WANT_MINICOREDUMPER_TRIGGER=1],
	[no], [WANT_MINICOREDUMPER_TRIGGER=0],
	[WANT_MINICOREDUMPER_TRIGGER=1])
AM_CONDITIONAL([COND_MINICOREDUMPER_TRIGGER], [test "$WANT_MINICOREDUMPER_TRIGGER" -eq 1 -a "x$with_dbus" = "xyes" -o "$HAVE_DBUS" -eq 1])

AC_ARG_WITH([libminicoredumper],
	    [AS_HELP_STRING([--without-libminicoredumper],
	    [build minicoredumper library @<:@default=with@:>@])])
AS_CASE(["$with_libminicoredumper"],
	[yes], [WANT_LIBMINICOREDUMPER=1],
	[no], [WANT_LIBMINICOREDUMPER=0],
	[WANT_LIBMINICOREDUMPER=1])
AM_CONDITIONAL([COND_LIBMINICOREDUMPER], [test "$WANT_LIBMINICOREDUMPER" -eq 1])

AC_ARG_WITH([minicoredumper_demo],
	    [AS_HELP_STRING([--with-minicoredumper_demo],
	    [build minicoredumper_demo program @<:@default=without@:>@])])
AS_CASE(["$with_minicoredumper_demo"],
	[yes], [WANT_MINICOREDUMPER_DEMO=1],
	[no], [WANT_MINICOREDUMPER_DEMO=0],
	[WANT_MINICOREDUMPER_DEMO=0])
AM_CONDITIONAL([COND_MINICOREDUMPER_DEMO], [test "$WANT_MINICOREDUMPER_DEMO" -eq 1])

dnl with or without -Werror
AC_ARG_WITH([werror],
	    [AS_HELP_STRING([--without-werror],
	    [compile with -Werror @<:@default=with@:>@])],
	    [MCD_WERROR=""],
	    [MCD_WERROR="-Werror"])

dnl last but not least
AC_OUTPUT([Makefile
	   src/Makefile
	   src/api/Makefile
	   src/dbus/Makefile
	   src/coreinject/Makefile
	   src/libminicoredumper/Makefile
	   src/libminicoredumper/minicoredumper-uninstalled.pc
	   src/libminicoredumper/minicoredumper.pc
	   src/minicoredumper/Makefile
	   src/minicoredumper_dbusd/Makefile
	   src/minicoredumper_trigger/Makefile
	   src/minicoredumper_demo/Makefile
	   lib/Makefile])
