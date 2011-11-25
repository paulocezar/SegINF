#!/bin/bash

make
sudo insmod seginf.ko

java -jar GUI/SegINF\ Firewall/dist/"SegINF Firewall.jar" 

make clean
rmmod seginf
