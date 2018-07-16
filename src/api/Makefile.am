##
## Copyright (c) 2015-2018 Linutronix GmbH. All rights reserved.
##
## SPDX-License-Identifier: BSD-2-Clause
##

man_MANS = mcd_dump_data_register_bin.3 mcd_dump_data_unregister.3 \
	   mcd_dump_data_register_text.3
EXTRA_DIST = $(man_MANS)

install-data-hook:
	cd $(DESTDIR)$(mandir)/man3 && \
	rm -f mcd_vdump_data_register_text.3 && \
	$(LN_S) mcd_dump_data_register_text.3 mcd_vdump_data_register_text.3

uninstall-hook:
	cd $(DESTDIR)$(mandir)/man3 && \
	rm -f mcd_vdump_data_register_text.3
