##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = coreinject

dist_man_MANS = coreinject.1

coreinject_SOURCES = main.c ../common/elf_dumplist.c
coreinject_LDADD = $(libelf_LIBS)
coreinject_CFLAGS = -g -Wall -std=c99 -D_GNU_SOURCE $(MCD_WERROR) \
		    -D_LARGEFILE64_SOURCE -I$(top_srcdir)/src/common \
		    $(libelf_CFLAGS)
