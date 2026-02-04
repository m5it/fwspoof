#!/bin/bash
# fwspoof.sh - Simple script to prevent spoofing attack on your http server.
#--
# How it works.
# a.)   Read data from tcpdump trough linux pipes.
#       Check for malformed / corrupted packets. If these packets repeat we treat it as BAD and we block.
#
# b.)   To prevent blocking whole network we memorize which ips/ranges are blocked and which attacking + checking timestamps of attacks.
#       Like this we can follow problems and approve action that should be taken.
#       1.) or block ip or range
#       2.) or unblock ip or range
#--

if [[ -t 0 ]]; then
	echo "ERROR: You need to pipe data into fwspoof.sh!"
	exit
fi

while read -r line; do
	echo "line: "$line
done

echo "Done!"
