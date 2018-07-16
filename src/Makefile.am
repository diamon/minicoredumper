##
## Copyright (c) 2015-2018 Linutronix GmbH. All rights reserved.
##
## SPDX-License-Identifier: BSD-2-Clause
##

SUBDIRS = api common

if COND_COREINJECT
SUBDIRS += coreinject
endif

if COND_MINICOREDUMPER
SUBDIRS += minicoredumper
endif

if COND_MINICOREDUMPER_REGD
SUBDIRS += minicoredumper_regd
endif

if COND_LIBMINICOREDUMPER
SUBDIRS += libminicoredumper
endif

if COND_MINICOREDUMPER_DEMO
SUBDIRS += minicoredumper_demo
endif

if COND_MINICOREDUMPER_TRIGGER
SUBDIRS += minicoredumper_trigger
endif
