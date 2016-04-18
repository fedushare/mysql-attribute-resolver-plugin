AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/shibboleth
plugin_LTLIBRARIES = mysqlattributeresolver.la

mysqlattributeresolver_la_SOURCES = \
	@PACKAGE_NAME@.cpp

mysqlattributeresolver_la_LDFLAGS = -module -avoid-version
mysqlattributeresolver_la_LIBADD = $(XMLSEC_LIBS)

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST =
