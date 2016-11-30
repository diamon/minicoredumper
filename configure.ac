###############################################################################
#
# Copyright (c) 2015-2016 Ericsson AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
###############################################################################

AC_PREREQ([2.69])
AC_INIT([minicoredumper], [2.0.0], [john.ogness@linutronix.de], [minicoredumper], [https://www.linutronix.de/minicoredumper])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AM_CONFIG_HEADER([config.h])

AC_SUBST([VERSION])

ISODATE=`date +%Y-%m-%d`
AC_SUBST([ISODATE])

AC_CANONICAL_HOST
AC_CANONICAL_BUILD
AC_LANG([C])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_AWK
AC_PROG_SED
AC_PROG_MKDIR_P
AC_PROG_CXX

LT_INIT

AC_DEFINE([_GNU_SOURCE], [], [GNU SOURCE])

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h stddef.h stdlib.h string.h sys/socket.h syslog.h unistd.h],
		 [], [AC_MSG_ERROR([required header missing!])])

AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_PROG_GCC_TRADITIONAL
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([dup2 ftruncate localtime_r memmove memset mkdir munmap pow socket strchr strdup strerror strndup strrchr strtol])

AC_CHECK_PROG([PKGCONFIG_CHECK], [pkg-config], [yes])
AS_IF([test "x$PKGCONFIG_CHECK" = xyes],
      [], AC_MSG_ERROR([pkg-config missing!]))

PKG_CHECK_MODULES([libelf], [libelf], [],
		  AC_CHECK_HEADERS([gelf.h], [libelf_LIBS=-lelf],
				   [AC_MSG_ERROR([gelf.h missing!])]))

PKG_CHECK_MODULES([libjsonc], [json-c], [],
		  AC_CHECK_HEADERS([json-c/json.h], [libjsonc_LIBS=-ljson-c],
				   [AC_MSG_ERROR([json-c/json.h missing!])]))

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

AC_ARG_WITH([minicoredumper_regd],
	    [AS_HELP_STRING([--without-minicoredumper_regd],
	    [build minicoredumper_regd daemon @<:@default=with@:>@])])
AS_CASE(["$with_minicoredumper_regd"],
	[yes], [WANT_MINICOREDUMPER_REGD=1],
	[no], [WANT_MINICOREDUMPER_REGD=0],
	[WANT_MINICOREDUMPER_REGD=1])
AM_CONDITIONAL([COND_MINICOREDUMPER_REGD],
	       [test "$WANT_MINICOREDUMPER_REGD" -eq 1])

AC_ARG_WITH([minicoredumper_trigger],
	    [AS_HELP_STRING([--without-minicoredumper_trigger],
	    [build minicoredumper_trigger tool @<:@default=with@:>@])])
AS_CASE(["$with_minicoredumper_trigger"],
	[yes], [WANT_MINICOREDUMPER_TRIGGER=1],
	[no], [WANT_MINICOREDUMPER_TRIGGER=0],
	[WANT_MINICOREDUMPER_TRIGGER=1])
AM_CONDITIONAL([COND_MINICOREDUMPER_TRIGGER],
	       [test "$WANT_MINICOREDUMPER_TRIGGER" -eq 1])

AC_ARG_WITH([libminicoredumper],
	    [AS_HELP_STRING([--without-libminicoredumper],
	    [build minicoredumper library @<:@default=with@:>@])])
AS_CASE(["$with_libminicoredumper"],
	[yes], [WANT_LIBMINICOREDUMPER=1],
	[no], [WANT_LIBMINICOREDUMPER=0],
	[WANT_LIBMINICOREDUMPER=1])
AM_CONDITIONAL([COND_LIBMINICOREDUMPER],
	       [test "$WANT_LIBMINICOREDUMPER" -eq 1])

AC_ARG_WITH([minicoredumper_demo],
	    [AS_HELP_STRING([--with-minicoredumper_demo],
	    [build minicoredumper_demo program @<:@default=without@:>@])])
AS_CASE(["$with_minicoredumper_demo"],
	[yes], [WANT_MINICOREDUMPER_DEMO=1],
	[no], [WANT_MINICOREDUMPER_DEMO=0],
	[WANT_MINICOREDUMPER_DEMO=0])
AM_CONDITIONAL([COND_MINICOREDUMPER_DEMO],
	       [test "$WANT_MINICOREDUMPER_DEMO" -eq 1])

AC_ARG_WITH([werror],
	    [AS_HELP_STRING([--without-werror],
	    [compile with -Werror @<:@default=with@:>@])])
AS_CASE(["$with_werror"],
	[yes], [MCD_WERROR="-Werror"],
	[no], [MCD_WERROR=""],
	[MCD_WERROR="-Werror"])

AC_ARG_VAR([MCD_CONF_PATH],
	   [path to minicoredumper configuration directory [SYSCONFDIR/minicoredumper]])
AS_IF([test "x$MCD_CONF_PATH" = x],
      [MCD_CONF_PATH="${sysconfdir}/minicoredumper"], [])

AC_ARG_VAR([MCD_DUMP_PATH],
	   [path to minicoredumper dump directory [LOCALSTATEDIR/crash/minicoredumper]])
AS_IF([test "x$MCD_DUMP_PATH" = x],
      [MCD_DUMP_PATH="${localstatedir}/crash/minicoredumper"], [])

AC_ARG_VAR([MCD_REGD_USER_GROUP],
	   [minicoredumper_regd user:group [root:root]])
AS_IF([test "x$MCD_REGD_USER_GROUP" = x],
      [MCD_REGD_USER_GROUP="root:root"], [])

MCD_CPPFLAGS="-Wall -D_GNU_SOURCE -D_LARGEFILE64_SOURCE $MCD_WERROR"
AC_SUBST([MCD_CPPFLAGS])

MCD_CFLAGS="-std=c99"
AC_SUBST([MCD_CFLAGS])

init_ddir="${sysconfdir}/init.d"
initdefaultsdir="${sysconfdir}/default"
AS_IF([test "x$runstatedir" = x], [runstatedir="${localstatedir}/run"], [])

AC_SUBST([init_ddir])
AC_SUBST([initdefaultsdir])
AC_SUBST([runstatedir])

AC_OUTPUT([Makefile
	   src/Makefile
	   src/api/Makefile
	   src/common/Makefile
	   src/coreinject/Makefile
	   src/libminicoredumper/Makefile
	   src/libminicoredumper/minicoredumper-uninstalled.pc
	   src/libminicoredumper/minicoredumper.pc
	   src/minicoredumper/Makefile
	   src/minicoredumper_regd/Makefile
	   src/minicoredumper_trigger/Makefile
	   src/minicoredumper_demo/Makefile])
