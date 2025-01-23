#!/bin/bash

sed -i '/define NDEBUG/,+2d' $@
