#
# Script to prevent spoofed attach on http server.
# Usage:
#     tcpdump -r out.cap -nn -s0 | python fwspoof.py
# or
#     tcpdump -i eno1 -nn -s0 | python fwspoof.py
#--
import atexit
import traceback
import threading
import subprocess
import sys, os, getopt
import json
import select
import base64
import time
import math
from functions import *

#--
#
Version = "0.7331.1"
#
def HELP():
	global Options
	print("HELP....\n")
	for k in Options:
		o=Options[k]
		print("{} => {}".format( o['short'], o['name'] ))
#
def VERSION():
	global Version
	print("v{}".format(Version))

#--
#
Config = {}
#
Options = {
	crc32b('-h'):{
		'name':'help',
		'short':'-h',
		'long':'--help',
		'accept':False, # accept value
		'value':False,
		'exec':HELP,
	},
	crc32b('-v'):{
		'name':'version',
		'short':'-v',
		'long':'--version',
		'accept':False, # accept value
		'value':False,
		'exec':VERSION,
	},
}
#
MemoryFlood = {
	# Ex.:
	# If "last_flag" change then "same_flag_count" reset and start from 0
	# key=first two octets of IP
	# val=object
	#"138.121":{"last_ts":0, "last_flag":"", "flag_count":0, }
	#"138.121":{"last_ts":0, "last_flag":"[S]", "flag_count":1, }
}

def perform_whois_lookup(ip):
	output = subprocess.check_output(['whois', ip]).decode('utf-8')
	for line in output.split('\n'):
		if 'CIDR' in line or 'Network Range' in line:
			return line.strip()

def perform_list_block():
	output = subprocess.check_output(['iptables','-L','FORWARD','-n']).decode('utf-8')
	for line in output.split('\n'):
		# DROP       all  --  45.187.56.0/22       0.0.0.0/0
		#if rmatch(line,"^DROP.*"):
		#	print("perform_list_block: ",line)
		a = pmatch(line,"^DROP.*all.*([0-9\.\/]+).*")
		print("perform_list_block: ",a)

def block_ip_range(cidr):
	# Block the IP range using iptables
	os.system(f'iptables -A FORWARD -s {cidr} -j DROP')

def unblock_ip_range(cidr):
	# Unblock the IP range using iptables
	os.system(f'iptables -D FORWARD -s {cidr}')

#
def cleaner():
	print("My function is running")
	#
	#mem = sorted(MemoryFlood.items(), key=lambda item:list(item[1].keys())[0])
	print("MemoryFlood( {} ): ".format( len(MemoryFlood) ))
	#
	while True:
		#sortDict(MemoryFlood,"flag_count")
		sortDict(MemoryFlood,"last_ts")
		for k in reversed(MemoryFlood):
			print("{} {} - {} => {}".format( k, todt(MemoryFlood[k]['last_ts']+cdts()), cts(), MemoryFlood[k] ))
			print("---------------------------------------------")
		
		print("Sleeping 3/s")
		time.sleep(3)

#
def run():
	global MemoryFlood, Options
	#
	for line in sys.stdin:
		# line Ex.: run() line 14:50:53.440085 IP 138.121.247.153.35544 > 192.168.0.69.443: Flags [S], seq 3300412588, win 64240, options [mss 1300,nop,wscale 8,nop,nop,sackOK], length 0
		# spoofed ips Ex.: 138.121.247.153
		# Normaly same numbers are Ex.: 138.121.x.x
		# 
		# ['14:50:53.440085', 'IP', '138.121.247.153.35544', '>', '192.168.0.69.443:', 'Flags', '[S],', 'seq', '3300412588,', 'win', '64240,', 'options', '[mss', '1300,nop,wscale', '8,nop,nop,sackOK],', 'length', '0\n']
		print("run() line",line);
		a = line.split(" ")
		#
		fto = ".".join(a[2].split(".")[:2]) # First two octets of IP
		ftt = ".".join(a[2].split(".")[:3]) # First three octets of IP
		#
		cfto = crc32b(fto)
		cftt = crc32b(ftt)
		#
		if cfto not in MemoryFlood:
			#
			MemoryFlood[cfto] = {
				"fto":fto,
				"last_ts" :tots(a[0]),
				"first_ts":tots(a[0]),
				"last_flag":a[6][:-1],
				"flag_count":1,
				"ftt":{
					cftt:{
						"ftt":ftt,
						"last_ts" :tots(a[0]),
						"first_ts":tots(a[0]),
						"last_flag":a[6][:-1],
						"flag_count":1,
					}
				}
			}
		else:
			# Flag is the same as previous was! (Warning)
			if MemoryFlood[cfto]["last_flag"] == a[6][:-1]:
				MemoryFlood[cfto]["last_ts"]    = tots(a[0])
				MemoryFlood[cfto]["flag_count"] += 1
			else:
				MemoryFlood[cfto]["last_ts"]    = tots(a[0])
				MemoryFlood[cfto]["flag_count"] = 1
				MemoryFlood[cfto]["last_flag"] = a[6][:-1]
			# # Check third octet
			oftt = MemoryFlood[cfto]["ftt"]
			if cftt in oftt:
				# cftt exists
				if oftt[cftt]["last_flag"] == a[6][:-1]:
					# same flag, increase count
					oftt[cftt]["last_ts"]    = tots(a[0])
					oftt[cftt]["flag_count"] += 1
				else:
					# flag change, zerro count
					oftt[cftt]["last_ts"]    = tots(a[0])
					oftt[cftt]["flag_count"] = 1
			else:
				# cftt dont exists
				oftt[cftt] = {
					"ftt":ftt,
					"last_ts" :tots(a[0]),
					"first_ts":tots(a[0]),
					"last_flag":a[6][:-1],
					"flag_count":1,
				}
			#
			MemoryFlood[cfto]["ftt"] = oftt

#
def main(argv):
	global Options, MemoryFlood
	#
	opt_help=False
	#
	try:
		opts, args = getopt.getopt(argv,genShortArgs(Options),genLongArgs(Options))
		#
		for opt, arg in opts:
			if crc32b(opt) in Options:
				o = Options[crc32b(opt)]
				if 'accept' in o and o['accept']:
					if type(Options[crc32b(opt)]['value']).__name__ == "int":
						Options[crc32b(opt)]['value'] = int(arg)
					else:
						Options[crc32b(opt)]['value'] = arg
				elif "exec" in o:
					o['exec']()
					sys.exit(1)
				else:
					Options[crc32b(opt)]['value'] = True
	except getopt.GetoptError:
		opt_help = True
	#
	if opt_help:
		print("HElp!")
		Options[crc32b('-h')]['exec']()
		sys.exit(1)
	
	#
	# Create a new thread that runs the my_function
	thread = threading.Thread(target=cleaner)
	thread.start()
	#
	#run()
	perform_list_block()
	#thread.join()

#--
if __name__ == '__main__':
	main(sys.argv[1:])
