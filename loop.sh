#!/bin/bash
#
while true; do tcpdump -r ../dumps/out2.cap -nn -s0 -l | python fwspoof.py -V; date; sleep 10; done
