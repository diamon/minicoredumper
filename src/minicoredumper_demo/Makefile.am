##
## Copyright (c) 2015-2018 Linutronix GmbH. All rights reserved.
##
## SPDX-License-Identifier: BSD-2-Clause
##

bin_PROGRAMS = minicoredumper_demo

minicoredumper_demo_SOURCES = main.c
minicoredumper_demo_CPPFLAGS = $(MCD_CPPFLAGS) \
			       -I$(top_srcdir)/src/api
minicoredumper_demo_LDADD = ../libminicoredumper/libminicoredumper.la
