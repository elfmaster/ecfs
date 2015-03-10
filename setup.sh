#!/bin/sh
for V in prod ; do for B in 32 64 ; do make V=$V B=$B ; done ; done
make install

