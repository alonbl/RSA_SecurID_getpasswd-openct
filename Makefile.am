AUTOMAKE_OPTIONS = foreign 1.10

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/m4/libtool.m4 $(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4 $(srcdir)/m4/ltsugar.m4 \
	$(srcdir)/m4/ltversion.m4 \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub

AM_CFLAGS = $(OPENCT_CFLAGS)

bin_PROGRAMS = RSA_SecurID_getpasswd
dist_man_MANS = RSA_SecurID_getpasswd.1

RSA_SecurID_getpasswd_SOURCES = RSA_SecurID_getpasswd.c
RSA_SecurID_getpasswd_LDADD = $(OPENCT_LIBS)
