#-- (5.2.2026) - by t3ch aka B.K. => w4d4f4k at gmail dot com
#--------------------------------------------------------------
# FWSpoof.py - Working on cleaning of trash. Working on making trash useful. So you are welcome until you can! *** Kisses my bad friends.
#--
# Script to prevent spoofed attack on http server.
# Trying to focus only on this kind of attack. For other trash have other scripts like FWTrash
#
# At moment script can run every X seconds to collect data and find trash... Data should be read from x.cap file that is created with tcpdump or similar software.
#
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
Config = {
	"file_block":"blocks.out",
}
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
Globals = {
	"run":False,
}
#-- MemoryFlood (used to find suspects by counting, key=flag_count and checking if flag repeats)
#   Save all data and count. If they reach block value then we block them. (simple).
#   After X time not active we unblock them! (simple).
# hard to understand! :x
MemoryFlood = {
	# Ex.:
	# If "last_flag" change then "same_flag_count" reset and start from 0
	# key=first two octets of IP
	# val=object
	#--
	#"138.121":{"last_ts":0, "last_flag":"", "flag_count":0, }
	#--
	# cftt = hash of ftt (three parts of ip)
	#"138.121":{"last_ts":0, "last_flag":"[S]", "flag_count":1, "cftt":{
	#    "ftt":{... same object as fto ...}
	#}}
}
#-- MemoryBlock
# Set when blocked.
# Unset if ips dont exists between suspects
MemoryBlock = {
	#      crc32b
	# keys = fto = {
		#       crc32b
		# keys = ftt = {"ftt":"first_three_octet_of_ip",}
	#}
	#"fto":{}
}

#
def check_blocks():
	global MemoryBlock
	output = subprocess.check_output(['iptables','-L','FORWARD','-n']).decode('utf-8')
	for line in output.split('\n'):
		# DROP       all  --  45.187.56.0/22       0.0.0.0/0
		if rmatch(line,"^DROP.*"):
			a = pmatch(line,r"\d+\.\d+\.\d+\.\d+(?:/\d+)?")
			# ['45.187.56.0/22', '0.0.0.0/0']
			print("debug len: {}, data: {}".format( len(a), a ))
			# match cidr only. Ex.: ip/22 or ip/24 or ip/whatever because preventing spoofed attacks.
			if len(a)>0 and rmatch(a[0],".*\\/\\d++$"):
				# debug len: 2, data: ['37.60.250.29', '0.0.0.0/0']
				# debug len: 2, data: ['45.156.129.52', '0.0.0.0/0']
				# debug len: 2, data: ['45.187.56.0/22', '0.0.0.0/0']
				# perform_list_block:  ['45.187.56.0/22', '0.0.0.0/0']
				print("perform_list_block: ",a)
				fto = ".".join(a[0].split(".")[:2])
				ftt = ".".join(a[0].split(".")[:3])
				#
				cfto = crc32b(fto)
				cftt = crc32b(ftt)
				print("load_block_list() fto: {}, ftt: {}".format( fto, ftt ))

	print("load_block_list() END len {}".format( len(MemoryBlock) ))
#
def block_ip_range(cidr):
	print("block_ip_range() START, cidr: {}".format(cidr))
	# Block the IP range using iptables
	os.system(f'iptables -A FORWARD -s {cidr} -j DROP')
#
def unblock_ip_range(cidr):
	# Unblock the IP range using iptables
	os.system(f'iptables -D FORWARD -s {cidr}')
#
def perform_block( MF ):
	global MemoryBlock
	print("perform_block() START MF: ",MF)
	#
	cfto = crc32b(MF['fto']) # cfto is crc32b of first two octet of ip
	#
	for k in MF['ftt']:
		MFF = MF['ftt'][k]
		if MFF['flag_count'] >= 5:
			print("perform_block() BLOCK ftt {} => {}".format( k, MFF ))
			cidr = "{}.0/24".format( MFF['ftt'] )
			cftt = k # cftt is crc32b of first three octet of ip
			# Save to MemoryBlock
			MemoryBlock[cfto] = {cftt:{"ftt":MFF['ftt'],}}
			# Block cidr
			block_ip_range( cidr )

# check for problems on count of bad things or time on these items..
# check() can block or unblock bad trash.
def check_suspect():
	global Globals
	print("check() START len MemoryFlood( {} ): ".format( len(MemoryFlood) ))
	#
	while Globals['run']:
		#sortDict(MemoryFlood,"flag_count")
		sortDict(MemoryFlood,"last_ts")
		for k in reversed(MemoryFlood):
			MF = MemoryFlood[k]
			if MF['last_flag']=='[S]' and MF['flag_count'] >= 20:
				perform_block( MF )
				print("---------------------------------------------")
		Globals['run'] = False

#
def parse( line:str ):
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
	CDTS = cdts()
	#
	if cfto not in MemoryFlood:
		#
		MemoryFlood[cfto] = {
			"fto"     :fto,
			"cdts"    :CDTS,
			"last_ts" :tots(a[0]),
			"first_ts":tots(a[0]),
			"last_flag":a[6][:-1],
			"flag_count":1,
			"ftt":{
				cftt:{
					"ftt"     :ftt,
					"cdts"    :CDTS,
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
				"cdts"    :CDTS,
				"last_ts" :tots(a[0]),
				"first_ts":tots(a[0]),
				"last_flag":a[6][:-1],
				"flag_count":1,
			}
		#
		MemoryFlood[cfto]["ftt"] = oftt


#
def load():
	global MemoryFlood, Options, Globals
	#
	Globals['run'] = True
	#
	for line in sys.stdin:
		parse( line )
	#
	check_suspect()
	#
	check_blocks()
	Globals['run'] = False

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
	#if opt_help:
	if Options[crc32b('-h')]['value']:
		print("HElp!")
		Options[crc32b('-h')]['exec']()
		sys.exit(1)
	#
	load_blocks()
	#
	# Create a new thread that runs the my_function
	#thread = threading.Thread(target=check)
	#thread.start()
	#
	load()
	#
	#thread.join()

#--
if __name__ == '__main__':
	main(sys.argv[1:])
