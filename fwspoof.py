#-- (5.2.2026) - by t3ch aka B.K. => w4d4f4k at gmail dot com
# v0.1 - 7.2.2026
#--------------------------------------------------------------
# FWSpoof.py - Working on cleaning of trash. Working on making trash useful. So you are welcome until you can! *** Kisses my bad friends.
#--
# Script to prevent spoofed attack on http server.
# Trying to focus only on this kind of attack. For other trash have other scripts like FWTrash.
# This kind of attack is not visible in normal logs of http servers because if this is necessary to use tools like tcpdump, wireshark or similar.
#
# At moment script can run every X seconds to collect data and find trash... Data should be read from x.cap file that is created with tcpdump or similar software.
#--
# v0.1
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
Version = "0.1.0"
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
#Config = {
#	"file_block":"blocks.out",
#}
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
	crc32b('-M'):{
		'name':'max_flag_count',
		'short':'-M',
		'long':'--max_flag_count',
		'accept':True, # accept value
		'value':20,
		#'exec':VERSION,
	},
	crc32b('-m'):{
		'name':'max_flag_count_per_cidr',
		'short':'-m',
		'long':'--max_flag_count_per_cidr',
		'accept':True, # accept value
		'value':5,
		#'exec':VERSION,
	},
	crc32b('-V'):{
		'name':'verbose',
		'short':'-V',
		'long':'--verbose',
		'accept':False, # accept value
		'value':False,
		#'exec':VERSION,
	},
	crc32b('-F'):{
		'name':'flag',
		'short':'-F',
		'long':'--flag',
		'accept':True, # accept value
		'value':'[S]',
		#'exec':VERSION,
	},
}
#
Globals = {
	"run":False,
}
#--
#
CheckBlock = {} # object of three octed of ip crc32bs. Ex.: 'crc32b'=True
#-- MemoryFlood (used to find suspects by counting, key=flag_count and checking if flag repeats)
#   Save all data and count. If they reach block value then we block them. (simple).
#   After X time not active we unblock them! (simple).
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
# a.) Set when blocked.
# b.) Set when listed from iptables
# c.) Unset if ips dont exists between suspects ( CheckBlock object )
MemoryBlock = {
	#      crc32b
	# keys = fto = {
		#       crc32b
		# keys = ftt = {"ftt":"first_three_octet_of_ip",}
	#}
	#"fto":{}
}
#
Stats = {
	"all":0,
	"uniq":0,
	"blocking":0,
	"unblocking":0,
	"blocked":0,
}

#--
#
def out(text:str,opts:list={}):
	global Options
	opt_prefix  = (opts['prefix'] if 'prefix' in opts else None)
	opt_verbose = (opts['verbose'] if 'verbose' in opts else Options[crc32b('-V')]['value'])
	if opt_verbose==False:
		return False
	if opt_prefix!=None:
		print("{} => {}".format(opt_prefix,text))
	else:
		print(text)
	return True

#--
#
def cleanup():
	global Options,Stats
	out("cleanup() START")
	#
	out("Stats: ")
	print(Stats)
	return True
#
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        # Let KeyboardInterrupt propagate
        out("Exception: Keyboard Interrupt: {}".format(exc_type),{'verbose':True})
        return
    # Extract traceback info
    tb = traceback.extract_tb(exc_traceback)
    # Get the last frame (most recent error)
    frame = tb[-1]
    filename, line, func, text = frame
    out(f"Exception: {exc_type.__name__}: {exc_value} (line {line} in {filename})",{'verbose':True,})
    # Optionally print full traceback
    traceback.print_exception(exc_type, exc_value, exc_traceback)
#
atexit.register(cleanup)
sys.excepthook = handle_exception

#--
#
def load_blocks():
	global MemoryBlock
	out("load_blocks() START")
	output = subprocess.check_output(['iptables','-L','FORWARD','-n']).decode('utf-8')
	for line in output.split('\n'):
		# DROP       all  --  45.187.56.0/22       0.0.0.0/0
		if rmatch(line,"^DROP.*"):
			a = pmatch(line,r"\d+\.\d+\.\d+\.\d+(?:/\d+)?")
			# ['45.187.56.0/22', '0.0.0.0/0']
			out("load_blocks() debug len: {}, data: {}".format( len(a), a ))
			# match cidr only. Ex.: ip/22 or ip/24 or ip/whatever because preventing spoofed attacks.
			if len(a)>0 and rmatch(a[0],".*\\/\\d++$"):
				# debug len: 2, data: ['37.60.250.29', '0.0.0.0/0']
				# debug len: 2, data: ['45.156.129.52', '0.0.0.0/0']
				# debug len: 2, data: ['45.187.56.0/22', '0.0.0.0/0']
				# perform_list_block:  ['45.187.56.0/22', '0.0.0.0/0']
				fto = ".".join(a[0].split(".")[:2])
				ftt = ".".join(a[0].split(".")[:3])
				#
				cfto = crc32b(fto)
				cftt = crc32b(ftt)
				out("load_blocks() fto({}): {}, ftt({}): {}".format( cfto, fto, cftt, ftt ))
				# Save to MemoryBlock
				if cfto not in MemoryBlock:
					MemoryBlock[cfto] = {}
				if cftt not in MemoryBlock[cfto]:
					MemoryBlock[cfto][cftt] = {"ftt":ftt,"cidr":a[0],}
	out("load_blocks() END len {}".format( len(MemoryBlock) ))
	out(MemoryBlock)
#-- check_blocks()
# used to unblock suspects when dont attacking anymore.
def check_blocks():
	global MemoryBlock, CheckBlock, Stats
	out("check_blocks() START")
	for k in MemoryBlock:
		if k not in CheckBlock:
			out("Unblocking {}".format( MemoryBlock[k] ))
			Stats['unblocking']+=1
			for k1 in MemoryBlock[k]:
				o = MemoryBlock[k][k1]
				out("unblocking {}".format( o['cidr'] ))
				unblock_ip_range( o['cidr'] )
		else:
			out("Leaving blocked {}".format( MemoryBlock[k] ))
#
def block_ip_range(cidr):
	out("block_ip_range() START, cidr: {}".format( cidr ))
	# Block the IP range using iptables
	os.system(f'iptables -A FORWARD -s {cidr} -j DROP')
#
def unblock_ip_range(cidr):
	out("unblock_ip_range() START, cidr: {}".format( cidr ))
	# Unblock the IP range using iptables
	os.system(f'iptables -D FORWARD -s {cidr} -j DROP')
#
def perform_block( MF ):
	global MemoryBlock
	#out("perform_block() START MF: ",MF)
	#
	cfto = crc32b(MF['fto']) # cfto is crc32b of first two octet of ip
	blocked=False
	#
	for k in MF['ftt']:
		MFF = MF['ftt'][k]
		# skip if already blocked. we get to here if one range start flooding later.
		#if MF['k'] not in MemoryBlock:
		#	continue
		if MF['k'] in MemoryBlock and k in MemoryBlock[MF['k']]:
			continue
		
		if MFF['flag_count'] >= Options[crc32b('-m')]['value']:
			out("perform_block() BLOCK ftt {} => {}".format( k, MFF ))
			cidr = "{}.0/24".format( MFF['ftt'] )
			cftt = k # cftt is crc32b of first three octet of ip
			# Block cidr
			block_ip_range( cidr )
			blocked=True
	return blocked
#
def exists_block( K, MF ):
	global MemoryBlock
	allin=0
	if K not in MemoryBlock:
		return False
	for k in MF['ftt']:
		if k in MemoryBlock[K]:
			allin+=1
	return True if allin==len(MF['ftt']) else False
# check for problems on count of bad things or time on these items..
# check() can block or unblock bad trash.
def check_suspect():
	global MemoryFlood, MemoryBlock, Stats
	#
	out("check_suspect() START, all: {}".format( len(MemoryFlood) ))
	if len(MemoryFlood)<=0:
		return False
	Stats['uniq'] = len(MemoryFlood)
	#
	while Globals['run']:
		#
		#for k in reversed(MemoryFlood):
		for k in MemoryFlood:
			MF = MemoryFlood[k]
			#out("check_suspect() k: {}, MF: {}".format( k, MF ))
# {'fto': '177.37', 'cdts': 1770422400, 'last_ts': 40121.319088, 'first_ts': 39185.956021, 'last_flag': '[S]', 'flag_count': 88, 'ftt': {
#    'cd176a0b': {'ftt': '177.37.46', 'cdts': 1770422400, 'last_ts': 40120.901163, 'first_ts': 39185.956021, 'last_flag': '[S]', 'flag_count': 119}, 
#    '23190b27': {'ftt': '177.37.44', 'cdts': 1770422400, 'last_ts': 40121.319088, 'first_ts': 39189.540114, 'last_flag': '[S]', 'flag_count': 110}, 
#    'ba105a9d': {'ftt': '177.37.47', 'cdts': 1770422400, 'last_ts': 40115.190599, 'first_ts': 39191.390454, 'last_flag': '[S]', 'flag_count': 19}, 
#    '541e3bb1': {'ftt': '177.37.45', 'cdts': 1770422400, 'last_ts': 40114.516531, 'first_ts': 39194.211224, 'last_flag': '[S]', 'flag_count': 111}}}
			#
			#if MF['last_flag']=='[S]' and MF['flag_count'] >= Options[crc32b('-M')]['value']:
			if MF['last_flag']==Options[crc32b('-F')]['value'] and MF['flag_count'] >= Options[crc32b('-M')]['value']:
				out("check_suspect() WARNING k: {}, MF: {}".format( k, MF ))
				#
				if exists_block(k,MF):
					#out("Already blocked! {} - {}".format( k, MF['fto'] ))
					out("check_suspect() Adding to CheckBlock D1 k: {}".format(MF['k']))
					CheckBlock[k]=True
					Stats['blocked']+=1
					continue
				else:
					out("Block dont exists! {} - {}".format( k, MF['fto'] ))
				#
				if perform_block( MF ):
					out("check_suspect() Adding to CheckBlock D2 k: {}".format(MF['k']))
					CheckBlock[MF['k']]=True
					Stats['blocking']+=1
					Stats['blocked']-=1
				out("---------------------------------------------")
			else:
				out("check_suspect() OK {}".format( MF ))
		Globals['run'] = False
	return True
#
def parse( line:str ):
	#run() line 12:05:54.906213 IP 177.37.46.55.19974 > 192.168.0.69.443: Flags [S], seq 1823246134, win 64240, options [mss 1300,nop,wscale 8,nop,nop,sackOK], length 0
	#parse() fto(7e1c7af0): 177.37, ftt(cd176a0b): 177.37.46

	a = line.split(" ")
	#
	fto = ".".join(a[2].split(".")[:2]) # First two octets of IP
	ftt = ".".join(a[2].split(".")[:3]) # First three octets of IP
	#
	sip = ".".join(a[2].split(".")[:4]) # source ip
	dip = ".".join(a[4].split(".")[:4]) # source ip
	#out("parse() sip: {} {} dip: {}".format( sip, a[3], dip ))
	Stats["all"]+=1
	# Check if sip between allowed, lets skip it so we wont block our selfs... :*
	
	#
	cfto = crc32b(fto)
	cftt = crc32b(ftt)
	CDTS = cdts()
	#
	if cfto not in MemoryFlood:
		#
		MemoryFlood[cfto] = {
			"fto"     :fto,
			"k"       :cfto,
			"cdts"    :CDTS,
			"last_ts" :tots(a[0]),
			"first_ts":tots(a[0]),
			"last_flag":a[6][:-1],
			"flag_count":1,
			"ftt":{
				cftt:{
					"ftt"     :ftt,
					"k"       :cftt,
					"cdts"    :CDTS,
					"last_ts" :tots(a[0]),
					"first_ts":tots(a[0]),
					"last_flag":a[6][:-1],
					"flag_count":1,
				},
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
	# # # Check third octet
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
			"k"  :cftt,
			"cdts"    :CDTS,
			"last_ts" :tots(a[0]),
			"first_ts":tots(a[0]),
			"last_flag":a[6][:-1],
			"flag_count":1,
		}
	#
	MemoryFlood[cfto]["ftt"] = oftt
#
def load_pcap():
	global MemoryFlood, Options, Globals
	#
	Globals['run'] = True
	#
	for line in sys.stdin:
		parse( line )
	#
	if check_suspect()==False:
		out("load_pcap() Failed. MemoryFood file.pcap empty!")
		return False
	#
	check_blocks()
	Globals['run'] = False
	return True
#
def start():
	#
	load_blocks()
	#
	# Create a new thread that runs the my_function
	#thread = threading.Thread(target=check)
	#thread.start()
	#
	load_pcap()
	#
	#thread.join()
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
		Options[crc32b('-h')]['exec']()
		sys.exit(1)
	#
	start()

#--
if __name__ == '__main__':
	main(sys.argv[1:])
