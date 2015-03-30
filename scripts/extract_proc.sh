#!/bin/sh

objcopy -O binary --set-section-flags .procfs.tgz=alloc --only-section=.procfs.tgz cores/sshd.25948 ptest.tgz

