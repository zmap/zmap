#!/bin/bash
set -e
set -o pipefail

MAJOR_REV=$((clang-format --version | awk '{print $3}' | cut -d '.' -f 1) || echo 0)
if [ $MAJOR_REV -lt 5 ]; then
	echo "error: need at least clang-format version 5.x"
	exit 1
fi

FORMAT_CMD="clang-format -i -style=file"

# No files passed, format everything
if [ $# -eq 0 ]; then
	echo "formatting all C code in src/ and lib/"
	find ./src -type f -name '*.c' -exec $FORMAT_CMD {} \;
	find ./src -type f -name '*.h' -exec $FORMAT_CMD {} \;
	find ./lib -type f -name '*.c' -exec $FORMAT_CMD {} \;
	find ./lib -type f -name '*.h' -exec $FORMAT_CMD {} \;
	exit 0
fi

# File names passed, format only those files
$FORMAT_CMD $@
