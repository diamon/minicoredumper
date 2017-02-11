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

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = COPYING.BSD COPYING.LGPLv2.1 \
	     etc/default/minicoredumper.in \
	     etc/init.d/minicoredumper.in \
	     etc/minicoredumper/generic.recept.json \
	     etc/minicoredumper/minicoredumper.cfg.json.in

init_d_SCRIPTS = etc/init.d/minicoredumper

initdefaults_DATA = etc/default/minicoredumper

mcdconfdir = $(MCD_CONF_PATH)
mcdconf_DATA = etc/minicoredumper/minicoredumper.cfg.json \
	       etc/minicoredumper/generic.recept.json

CLEANFILES = $(init_d_SCRIPTS) $(initdefaults_DATA) \
	     etc/minicoredumper/minicoredumper.cfg.json

do_subst = sed -e 's,[@]sbindir[@],$(sbindir),g' \
	   -e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	   -e 's,[@]runstatedir[@],$(runstatedir),g' \
	   -e 's,[@]init_ddir[@],$(init_ddir),g' \
	   -e 's,[@]initdefaultsdir[@],$(initdefaultsdir),g' \
	   -e 's,[@]MCD_DUMP_PATH[@],$(MCD_DUMP_PATH),g' \
	   -e 's,[@]MCD_REGD_USER_GROUP[@],$(MCD_REGD_USER_GROUP),g'

etc/init.d/minicoredumper: etc/init.d/minicoredumper.in Makefile
	$(MKDIR_P) etc/init.d
	$(do_subst) < $< > $@
	chmod 0755 $@

etc/default/minicoredumper: etc/default/minicoredumper.in Makefile
	$(MKDIR_P) etc/default
	$(do_subst) < $< > $@

etc/minicoredumper/minicoredumper.cfg.json: etc/minicoredumper/minicoredumper.cfg.json.in Makefile
	$(MKDIR_P) etc/minicoredumper
	$(do_subst) < $< > $@

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(MCD_DUMP_PATH)
	chmod 0700 $(DESTDIR)$(MCD_DUMP_PATH)
	$(MKDIR_P) $(DESTDIR)$(runstatedir)

DIST_SUBDIRS = src
SUBDIRS = src
