#!/bin/sh

# orig https://stackoverflow.com/questions/34942796/shell-cmd-date-without-new-line-in-the-end
LOG_FILE="./angr-mem.log"
rm -f $LOG_FILE

### wait for process spawn
while true; do
ps -C pypy > /dev/null
if [ $? -eq 0 ]; then
    echo "[*] process spawned."
    break
fi
sleep 0.5
done

### monitor process
while true; do
ps -C pypy > /dev/null
if [ $? -gt 0 ]; then
    echo "[*] process exited."
    exit
fi
(echo -n `date +'%s'` ' '; ps -C pypy -o pid=,%mem=,vsz=) >> $LOG_FILE
# gnuplot ./gnuplot.script
sleep 10
done