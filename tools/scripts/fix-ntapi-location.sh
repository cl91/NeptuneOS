#!/bin/bash

sed -i -E ':begin;$!N;$!N;s/([A-Z_a-z]+)\nNTAPI\n/NTAPI \1 /;tbegin;P;D' $@
sed -i -E 's/([A-Z_a-z]+) NTAPI/NTAPI \1/g' $@
sed -i -E ':begin;$!N;$!N;s/([A-Z_a-z]+)\nWINAPI\n/WINAPI \1 /;tbegin;P;D' $@
sed -i -E 's/([A-Z_a-z]+) WINAPI/WINAPI \1/g' $@
sed -i -E ':begin;$!N;$!N;s/WINBASEAPI\n([A-Z_]+)/\1 WINBASEAPI/;tbegin;P;D' $@
sed -i -E 's/([A-Z_]+) DECLSPEC_HOTPATCH/DECLSPEC_HOTPATCH \1/g' $@
