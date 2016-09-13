##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
##

bin_PROGRAMS = coreinject

dist_man_MANS = coreinject.1

coreinject_SOURCES = main.c
coreinject_CPPFLAGS = $(MCD_CPPFLAGS) \
		      -I$(top_srcdir)/src/common \
		      $(libelf_CFLAGS)
coreinject_LDADD = ../common/libmcdelf.a $(libelf_LIBS)
