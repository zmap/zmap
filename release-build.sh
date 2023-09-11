#!/bin/bash
cmake \
  -DENABLE_DEVELOPMENT=off \
  -DZMAP_VERSION=$1 \
  -DENABLE_LOG_TRACE=off \
  .
make
