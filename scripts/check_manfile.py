#!/usr/env python

import sys

#let's parse strings in python!
options = []
with open("src/zopt.ggo.in") as fd:
    for l in fd:
        if l.startswith("option "):
            option = l.split()[1].lstrip('"').rstrip('"')
            options.append(option)

man = open('src/zmap.1.ronn').read()
failures = False
for option in options:
    if option not in man:
        failures = True
        sys.stderr.write("ZMap option missing from man file: %s\n" % option)

if failures:
    sys.exit(1)
