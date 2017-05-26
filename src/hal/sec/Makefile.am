lib_LIBRARIES = libsecurity.a
AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS)

libsecurity_a_SOURCES = security.c nanoecc/ecc.c nanoecc/ecc.h aes/aes.h
libsecurity_a_CPPFLAGS = -I$(top_srcdir)/src

all-local:
	$(MKDIR_P) $(top_srcdir)/libs && cp $(lib_LIBRARIES) $(top_srcdir)/libs

clean-local:
	$(RM) -r libsecurity.a

