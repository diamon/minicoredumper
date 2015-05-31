dist_man_MANS = mcd_dump_data_dbus_start.3 mcd_dump_data_register_bin.3 \
		mcd_dump_data_unregister.3 mcd_dump_data_dbus_stop.3 \
		mcd_dump_data_register_text.3

install-data-hook:
	cd $(DESTDIR)$(mandir)/man3 && \
	rm -f mcd_vdump_data_register_text.3 && \
	$(LN_S) mcd_dump_data_register_text.3 mcd_vdump_data_register_text.3

uninstall-hook:
	rm -f mcd_vdump_data_register_text.3
