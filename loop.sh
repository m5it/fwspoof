#!/bin/bash
#
while true; do tcpdump -r out.cap -nn -s0 -l | python fwspoof.py -D -C INPUT; date; sleep 10; done
