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
#
def pmatch(input,regex):
	ret=[]
	a = re.findall( regex, input, flags=re.IGNORECASE )
	#print("pmatch a: {}".format(a))
	if a is not None:
		for v in a:
			ret.append( v )
	return ret

#-- FILE
#
def file_exists( filename:str ) -> bool:
	return os.path.exists( filename )
#
def file_write( filename, data, overwrite=False ):
	f=None
	try:
		if file_exists(filename) and overwrite==True:
			f = open(filename,"w")
			f.seek(0)
			f.truncate()
		elif file_exists(filename)==False:
			f = open(filename,"w")
		else:
			f = open(filename,"a")
		f.write("{}".format( data ))
		f.close()
	except Exception as E:
		print("ERROR: file_write() on file: {}, len: {}, E: {}".format( filename, len(data), E ))
#
def file_overline( filename, xobj, at, isString=False ):
	#--
	#
	if os.path.exists( filename )==False:
		return False;
	
	lines=[]
	with open(filename,'r') as f:
		lines = f.readlines()
	#
	with open(filename,'w') as f:
		for i,line in enumerate(lines,0):
			if i==at:
				if isString==False:
					f.writelines( "{}\n".format( json.dumps(xobj) ) )
				else:
					f.writelines( "{}\n".format( line.strip() ) )
			else:
				f.writelines( "{}\n".format( line.strip() ) )
