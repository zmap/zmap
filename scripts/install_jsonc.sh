#!/bin/bash
curl -L https://github.com/json-c/json-c/archive/json-c-0.12-20140410.tar.gz | tar -xz

cd json-c-json-c-0.12-20140410
./autogen.sh
./configure
make
sudo make install
