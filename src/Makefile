INCLUDE+=-I../lib -I./ -Ioutput_modules
LDFLAGS+=-pthread
LDLIBS+=-lpcap -lgmp -lm
TARGETS=zmap
VPATH=../lib:output_modules:probe_modules
PREFIX=/usr/local

INSTALL=install
INSTALLDATA=install -m 644
mandir=$(PREFIX)/man/man1/
oldmanfile=/usr/share/man/man1/zmap.1
bindir=$(PREFIX)/sbin

# Hardening and warnings for building with gcc
# Maybe add -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
GCCWARNINGS = -Wall -Wformat=2 -Wno-format-nonliteral\
-pedantic -fno-strict-aliasing \
-Wextra \
-Wfloat-equal -Wundef -Wwrite-strings -Wredundant-decls  \
-Wnested-externs -Wbad-function-cast -Winit-self         \
-Wmissing-noreturn -Wnormalized=id    \
-Wstack-protector

GCCHARDENING=-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIC --param ssp-buffer-size=1
LDHARDENING=-z relro -z now

EXTRACFLAGS=-std=gnu99 -g -O2 $(GCCHARDENING) $(GCCWARNINGS) $(EXTRA_CFLAGS) -Werror
EXTRALDFLAGS= $(LDHARDENING)

CFLAGS+=$(INCLUDE) $(EXTRACFLAGS)
LDFLAGS+=$(EXTRALDFLAGS)

probemodules=module_tcp_synscan.o module_icmp_echo.o module_udp.o #ADD YOUR PROBE MODULE HERE
outputmodules= module_csv.o #ADD YOUR OUTPUT MODULE HERE

objects=constraint.o blacklist.o cyclic.o logger.o send.o recv.o state.o monitor.o zopt_compat.o zmap.o random.o output_modules.o packet.o probe_modules.o ${probemodules} ${outputmodules} validate.o rijndael-alg-fst.o get_gateway.o aesrand.o fieldset.o
redis_objects=module_redis.o redis.o

ifeq ($(REDIS), true)
	LDLIBS+=-lhiredis
	objects+=$(redis_objects)
	CFLAGS+=-DREDIS
endif

ifeq ($(JSON), true)
	LDLIBS+=$(shell pkg-config --libs json-c)
	CFLAGS+=-DJSON $(shell pkg-config --cflags json-c)
	objects+=module_json.o
endif

all: $(TARGETS)

$(TARGETS):
	$(CC) $(CFLAGS) $(DFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

zmap: $(objects) 

zopt_compat.o: zopt.c

zopt.c zopt.h: zopt.ggo
	gengetopt -C --no-help --no-version -i $^ -F $*

install: zmap
	$(INSTALL) zmap $(bindir)/zmap
	test -d /etc/zmap || (mkdir /etc/zmap && $(INSTALLDATA) ../conf/* /etc/zmap/)
	test -f $(oldmanfile) && rm -f $(oldmanfile) && mandb -f $(oldmanfile) || /bin/true # remove old man page if it's there
	test -d $(mandir) || mkdir -p $(mandir)
	$(INSTALLDATA) ./zmap.1 $(mandir)
	@echo "\n**************\nSuccess! ZMap is installed. Try running (as root):\nzmap -p 80 -N 10 -B 1M -o -\n**************"

uninstall:
	test -f $(oldmanfile) && rm -f $(oldmanfile) && mandb -f $(oldmanfile) || /bin/true # remove old man page if it's there
	test -f $(mandir)/zmap.1 && rm -f $(mandir)/zmap.1 && mandb -f $(mandir)/zmap.1 || /bin/true # remove current man page if it's there
	rm -f $(bindir)/zmap


clean:
	-rm -f $(objects) $(redis_objects) $(TARGETS)

.PHONY: install clean

