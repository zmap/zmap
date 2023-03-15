#!/usr/bin/env bash
ZMAP_CONTAINER_TAG=${ZMAP_CONTAINER_TAG:-'latest'}
docker build -f builder.dockerfile -t ghcr.io/zmap/builder:$ZMAP_CONTAINER_TAG .
docker push ghcr.io/zmap/builder:$ZMAP_CONTAINER_TAG
