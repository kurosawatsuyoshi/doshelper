mod_doshelper.la: mod_doshelper.slo
	$(SH_LINK) $(LIBS) -rpath $(libexecdir) -module -avoid-version  mod_doshelper.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_doshelper.la
