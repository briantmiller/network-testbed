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

PROG1    := satnetem
SRCS1    := $(PROG1).c

PROG2    := satrelay
SRCS2    := $(PROG2).c

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -Wall -Wextra
LDLIBS  += -lm

PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
INSTALL ?= install

.PHONY: all clean install uninstall

all: $(PROG1) $(PROG2)

$(PROG1): $(SRCS1)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS1) $(LDLIBS)

$(PROG2): $(SRCS2)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS2) $(LDLIBS)

install: $(PROG1)
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0755 $(PROG1) $(DESTDIR)$(SBINDIR)/$(PROG1)
	$(INSTALL) -m 0755 $(PROG2) $(DESTDIR)$(SBINDIR)/$(PROG2)

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/$(PROG1)
	rm -f $(DESTDIR)$(SBINDIR)/$(PROG2)

clean:
	rm -f $(PROG1)
	rm -f $(PROG2)
