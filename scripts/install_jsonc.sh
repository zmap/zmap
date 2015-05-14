#!/bin/bash
rm -rf json-c-json-c-0.12-20140410
curl -L https://github.com/json-c/json-c/archive/json-c-0.12-20140410.tar.gz | tar -xz

# Get rid of pesky -Werror
cp json_c_new_Makefile.am.inc json-c-json-c-0.12-20140410/Makefile.am.inc

# Actually build the damn thing
cd json-c-json-c-0.12-20140410
./autogen.sh
./configure
make

# Install it
#sudo make install
