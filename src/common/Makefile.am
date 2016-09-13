##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

noinst_LIBRARIES = libmcdelf.a libmcdident.a
noinst_LTLIBRARIES = libmcdident.la

libmcdelf_a_SOURCES = common.h elf_dumplist.c
libmcdelf_a_CPPFLAGS = $(MCD_CPPFLAGS)
libmcdelf_a_CFLAGS = $(MCD_CFLAGS)

libmcdident_a_SOURCES = common.h invalid_ident.c
libmcdident_a_CPPFLAGS = $(MCD_CPPFLAGS)
libmcdident_a_CFLAGS = $(MCD_CFLAGS)

libmcdident_la_SOURCES = common.h invalid_ident.c
libmcdident_la_CPPFLAGS = $(libmcdident_a_CPPFLAGS)
libmcdident_la_CFLAGS = $(libmcdident_a_CFLAGS)
