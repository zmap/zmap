#!/bin/bash
FAIL=0
for filepath in "$@"; do
	clang-format -style=file  -output-replacements-xml $filepath \
		| grep '<replacement ' \
		> /dev/null
	if [ $? -ne 1 ]
	then
		FAIL=1
		(>&2 echo "$filepath did not match clang-format")
	fi
done

if [ $FAIL -ne 0 ]
then
	exit 1
fi
