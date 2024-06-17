#!/bin/bash

sed -i ':begin;$!N;$!N;s/\n\n\/\* EOF \*\///;tbegin;P;D' $@
