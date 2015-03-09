#!/bin/bash
#This requires a few different platform targets to be created, so we can support 32bit on 64bit systems.
make V=prod B=64
make V=shared B=32 
make V=shared B=64
sudo make install
