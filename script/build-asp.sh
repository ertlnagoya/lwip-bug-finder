#!/bin/sh
ORIG=`pwd`
cd asp-gr_peach_gcc-mbed/asp-1.9.2-utf8/cfg/cfg

### obtain configuration
if [ ! -e cfg-linux-static-1_9_5.gz ]; then
wget http://toppers.jp/download.cgi/cfg-linux-static-1_9_5.gz
fi
tar zxvf cfg-linux-static-1_9_5.gz

cd $ORIG
cd asp-gr_peach_gcc-mbed/examples/httpsample
make depend; make
cp asp $ORIG/bin/httpsample.elf
cp asp.bin $ORIG/bin/httpsample.bin