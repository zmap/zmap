#!/usr/bin/env python3
#
# CI runs this script to verify that options appearing in ZTools' ggo.in files
# also appear in their .ronn files.  It does not check that `make manpages` has
# actually been run.
#
# This script assumes it's being run from the root of the zmap repository.
#

import sys

checks = [
    ("zopt.ggo.in", "zmap.1.ronn"),
    ("zbopt.ggo.in", "zblocklist.1.ronn"),
    ("zitopt.ggo.in", "ziterate.1.ronn"),
    ("ztopt.ggo.in", "ztee.1.ronn")
]

failures = False

for ggo, ronn in checks:
    options = []
    with open("src/" + ggo) as fd:
        for l in fd:
            if l.startswith("option "):
                option = l.split()[1].lstrip('"').rstrip('"')
                options.append(option)

    man = open("src/" + ronn).read()

    for option in options:
        if option not in man:
            failures = True
            sys.stderr.write(f"option \"{option}\" is present in \"{ggo}\" but missing from man file \"{ronn}\"\n")
    sys.stderr.flush()

if failures:
    sys.exit(1)
