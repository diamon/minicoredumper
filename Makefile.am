##
## Author: John Ogness
##
## This file has been put into the public domain.
## You can do whatever you want with this file.
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
