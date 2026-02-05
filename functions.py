import zlib,re
from datetime import datetime,date
#
def genShortArgs(Options):
	#global Options
	ret=""
	for k in Options:
		o = Options[k]
		if "accept" in o and o["accept"]:
			ret = "{}{}:".format(ret,o["short"][1:len(o["short"])])
		else:
			ret = "{}{}".format(ret,o["short"][1:len(o["short"])])
	return ret
#
def genLongArgs(Options):
	#global Options
	ret=[]
	for k in Options:
		o = Options[k]
		ret.append(o['long'])
	return ret
#
def tots( data:str ):
	parts = data.split('.')
	hours, minutes, seconds = map(int, parts[0].split(':'))
	microseconds = int(parts[1])
	return (hours * 3600) + (minutes * 60) + seconds + (microseconds / 1e6)
#
def cts():
	current_time = datetime.now()
	hours = current_time.hour
	minutes = current_time.minute
	seconds = current_time.second
	microseconds = current_time.microsecond
	return (hours * 3600) + (minutes * 60) + seconds + (microseconds / 1e6)
#
def cdts():
	return int((date.today() - date(1970, 1, 1)).total_seconds())
#
def todt( data:float ):
	timestamp_seconds = int(data)
	timestamp_microseconds = int((data-timestamp_seconds) * 10**-6)
	return datetime.utcfromtimestamp(timestamp_seconds + (timestamp_microseconds / 1e6))
#
def sortDict(a,k):
	n=len(a)
	while True:
		nxt = None
		tmp = None
		b   = iter(a)
		i   = next(b,None)
		for j in range(n):
			nxt = next(b,None)
			if nxt==None:
				continue
			if a[i][k]>a[nxt][k]:
				tmp = a[i]
				a[i] = a[nxt]
				a[nxt] = tmp
			i=nxt
		if tmp==None:
			break
#
def crc32b(text):
	return "%x"%(zlib.crc32(text.encode("utf-8")) & 0xFFFFFFFF)
#
def rmatch(input,regex):
	x = re.match( regex, input )
	if x != None:
		return x
	else:
		return False
