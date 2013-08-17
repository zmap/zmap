CC=gcc

CFLAGS=-Wall -pedantic -Wextra -std=gnu99 -I../lib -I./ -Ioutput_modules -O2 -g
LDFLAGS=-g -pthread
LDLIBS= -lpcap -lgmp -lm
TARGETS=zmap
VPATH=../lib:output_modules:probe_modules
PREFIX=/usr/local

INSTALL=install
INSTALLDATA=install -m 644
mandir=/usr/share/man/man1/
bindir=$(PREFIX)/sbin

# Hardening and warnings for building with gcc
#M aybe add -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
#-Wold-style-definition -Wswitch-enum 
GCCWARNINGS = -Wall -fno-strict-aliasing -W -Wfloat-equal -Wundef      \
-Wpointer-arith														   \
-Wwrite-strings -Wredundant-decls -Wchar-subscripts -Wcomment          \
-Wformat=2 -Wwrite-strings -Wredundant-decls -Wno-unused-but-set-variable    \
-Wnested-externs -Wbad-function-cast -Winit-self         \
-Wmissing-field-initializers										   \
-Waddress -Wmissing-noreturn -Wnormalized=id    \
-Woverride-init -Wstrict-overflow=1 -Wextra -Warray-bounds             \
-Wstack-protector -Wformat -Wformat-security -Wpointer-sign -Wno-format-nonliteral -Wno-format-y2k
GCCHARDENING=-D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIC --param ssp-buffer-size=1
LDHARDENING=-z relro -z now

EXTRACFLAGS=-g -O2 $(EXTRA_CFLAGS) $(GCCHARDENING) $(GCCWARNINGS) -Werror
EXTRALDFLAGS= $(LDHARDENING)

CFLAGS+=-Wall $(INCLUDE) $(EXTRACFLAGS)
LDFLAGS+=$(EXTRALDFLAGS)

modules=module_tcp_synscan.o module_icmp_echo.o module_udp.o #ADD YOUR MODULE HERE

objects=constraint.o blacklist.o cyclic.o logger.o send.o recv.o state.o monitor.o zopt.o zmap.o random.o output_modules.o module_simple_file.o module_extended_file.o packet.o probe_modules.o ${modules} validate.o rijndael-alg-fst.o get_gateway.o aesrand.o

ifeq ($(REDIS), true)
	LDLIBS+=-lhiredis
	objects+=module_redis.o redis.o
	CFLAGS+=-DREDIS
endif

all: $(TARGETS)

$(TARGETS):
	$(CC) $(CFLAGS) $(DFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

zmap: $(objects) 

zopt.c zopt.h: zopt.ggo
	gengetopt -C --no-help --no-version -i $^ -F $*

install: zmap
	$(INSTALL) zmap $(bindir)/zmap
	test -d /etc/zmap || (mkdir /etc/zmap && $(INSTALLDATA) ../conf/* /etc/zmap/)
	$(INSTALLDATA) ./zmap.1 $(mandir)
	echo "\n\n\n\n**************\nSuccess! ZMap is installed. Try running (as root):\nzmap -p 80 -N 10 -B 1M -o -\n**************"

clean:
	-rm -f $(objects) $(TARGETS)

.PHONY: install clean

