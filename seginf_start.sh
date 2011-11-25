#!/bin/bash

cd core
make
insmod seginf.ko
cd ..

java -jar GUI/SegINF\ Firewall/dist/"SegINF Firewall.jar" 

cd core
make clean
cd ..

rmmod seginf

