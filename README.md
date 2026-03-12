# (5.2.2026) - by t3ch aka B.K. => w4d4f4k at gmail dot com
#- v0.2 - 12.2.2026 - added syn / reset attack support
#- v0.1 - 7.2.2026
#-        8.2.2026  - first bugs. It block just one range instead of four. Quick fix is here.
#-        11.3.2026 - noted bug with passing arguments from terminal to program. looks old python versions have problems and dont works as expected.
#-                    i mean when running program with arguments Ex.: python3 fwspoof.py -D -S -M 15 -m 2 -C INPUT -V
#--------------------------------------------------------------
# FWSpoof.py - Working on cleaning of trash. Working on making trash useful. So you are welcome until you can! *** Kisses my bad friends.
#
# Script to prevent spoofed attack on http server.
# Trying to focus only on this kind of attack. For other trash have other scripts like FWTrash.
# This kind of attack is not visible in normal logs of http servers because of this is necessary to use tools like tcpdump, wireshark or similar.
#
# At moment script can run every X seconds to collect data and find trash... Data should be read from x.cap file that is created with tcpdump or similar software.
#--
# v0.1             supported SYN attack
# v0.2 (12.2.2026) supported SYN/RESET attack
#
# First we save received packets with tcpdump, like this we can filter out what is not necessary to read.
# Second we read saved packets and pass trough pipe to fwspoof to analyze data.
# fwspoof decide depend on configuration or block or unblock suspects.
#
# Usage (10.0.5.10) is server that is getting attacked:
#  1.)   tcpdump -i enp1s0 -nn -s0 tcp and dst 10.0.5.10 and (not port 22) -w out.cap -G 1800 --print
#  or
#        tcpdump -i enp1s0 -nn -s0 tcp and dst 10.0.5.10 and (not port 22) -w out.cap -G 1800
#
#  2.)   tcpdump -r out.cap -nn -s0 | python fwspoof.py -V
#  3.)   python fwspoof.py -h
#        python fwspoof.py -v
#        python fwspoof.py -V # verbose | debug output
#--
# Examples
tcpdump -r your_capture.pcap -c 1000  # Skip first 1000 packets
#
dd if=your_capture.pcap of=partial.pcap skip=1000 bs=1
tcpdump -r partial.pcap
