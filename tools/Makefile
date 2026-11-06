# Makefile for satnetem, the netem/rtnetlink Starlink-like link emulator.
#
#   make                 build satnetem
#   make install         install to $(DESTDIR)$(PREFIX)/sbin (default /usr/local/sbin)
#   make uninstall       remove it again
#   make clean           remove build output
#
# CC, CFLAGS, CPPFLAGS, LDFLAGS, PREFIX and DESTDIR can be overridden, e.g.
#   make CC=clang CFLAGS=-O3
#   make install PREFIX=/usr DESTDIR=/tmp/pkgroot

PROG    := satnetem
SRCS    := satnetem.c

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -Wall -Wextra
LDLIBS  += -lm

PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
INSTALL ?= install

.PHONY: all clean install uninstall

all: $(PROG)

$(PROG): $(SRCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(LDLIBS)

install: $(PROG)
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0755 $(PROG) $(DESTDIR)$(SBINDIR)/$(PROG)

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/$(PROG)

clean:
	rm -f $(PROG)
