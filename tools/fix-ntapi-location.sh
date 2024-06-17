#!/bin/bash

sed -i -E ':begin;$!N;$!N;s/([A-Z_a-z]+)\nNTAPI\n/NTAPI \1 /;tbegin;P;D' $@
sed -i -E 's/([A-Z_a-z]+) NTAPI/NTAPI \1/g' $@
