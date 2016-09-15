#!/bin/bash
set -e
for filepath in "$@"; do
	clang-format -style=file -i $filepath
done
