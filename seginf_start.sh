#!/bin/bash

make
sudo insmod seginf.ko
make clean

java -jar "SegINF Firewall.jar"


