##
## Copyright (c) 2015-2016 Linutronix GmbH
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
## 1. Redistributions of source code must retain the above copyright notice,
##    this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright notice,
##    this list of conditions and the following disclaimer in the documentation
##    and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
## LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
## CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
## SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
## INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
## CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
## ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
## POSSIBILITY OF SUCH DAMAGE.
##

sbin_PROGRAMS = minicoredumper

man_MANS = minicoredumper.cfg.json.5 minicoredumper.recept.json.5 \
	   minicoredumper.1
EXTRA_DIST = $(man_MANS)

minicoredumper_SOURCES = corestripper.c corestripper.h \
			 prog_config.c prog_config.h
minicoredumper_CPPFLAGS = $(MCD_CPPFLAGS) \
			  -I$(top_srcdir)/lib \
			  -I$(top_srcdir)/src/api \
			  -I$(top_srcdir)/src/common \
			  -I$(top_srcdir)/src/libminicoredumper \
			  -DMCD_CONF_PATH=\"$(MCD_CONF_PATH)\" \
			  $(libelf_CFLAGS) $(libjsonc_CFLAGS)
minicoredumper_CFLAGS = $(MCD_CFLAGS)
minicoredumper_LDADD = ../common/libmcdelf.a \
		       ../common/libmcdident.a \
		       $(libelf_LIBS) $(libjsonc_LIBS) \
		       -lthread_db -lpthread -lrt
