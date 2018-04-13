PREFIX=

ifeq (,$(NOVERSION))
VERSION:=$(shell cat VERSION)
override CFLAGS+=-DPREFIX=\"$(PREFIX)\" -D_ACCESS_VERSION=\"$(VERSION)\"
else
override CFLAGS+=-DPREFIX=\"$(PREFIX)\"
endif

ifeq (,$(NOLCRYPT))
override LDFLAGS+=-lcrypt
endif

ifneq (,$(DEBUG))
override CFLAGS+=-Wall -O0 -g
else
override CFLAGS+=-O2
endif

ifneq (,$(STATIC))
override LDFLAGS+=-static
endif

ifneq (,$(STRIP))
override LDFLAGS+=-s
endif

ifneq (,$(PIE))
# Linux and other systems with gcc and binutils
override CFLAGS+=-fPIE -DWITH_STATIC_MEMORY
override LDFLAGS+=-pie -Wl,-z,relro
endif

# Use host libc extensions such as memmem
ifneq (,$(EXTS))
override CFLAGS+=-D_GNU_SOURCE
endif

all: access

SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)
%.o: %.c VERSION $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<
access: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

install: access
	install -m0755 access $(DESTDIR)$(PREFIX)/bin/
	chmod 4711 $(DESTDIR)$(PREFIX)/bin/access

docs: access.8 access.conf.5
	mandoc -Tascii access.8 >access.8.txt
	mandoc -Tascii access.conf.5 >access.conf.5.txt

install-man:
	-@install -d $(DESTDIR)$(PREFIX)/man/man8
	-@install -d $(DESTDIR)$(PREFIX)/man/man5
	install -m0644 access.8 $(DESTDIR)$(PREFIX)/man/man8/
	install -m0644 access.conf.5 $(DESTDIR)$(PREFIX)/man/man5/

distclean: clean
clean:
	rm -f *.o access
