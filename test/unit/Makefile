# Standalone unit-test build for ja4ts formatter.
# Usage: make -C test/unit run

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -std=c99 -g -O0
SRCDIR  := ../../src

test_ja4ts: test_ja4ts.c $(SRCDIR)/probe_modules/module_tcp_synscan.c $(SRCDIR)/probe_modules/module_tcp_synscan.h
	$(CC) $(CFLAGS) -I$(SRCDIR) -DJA4TS_UNIT_TEST test_ja4ts.c -o test_ja4ts

run: test_ja4ts
	./test_ja4ts

clean:
	rm -f test_ja4ts

.PHONY: run clean
