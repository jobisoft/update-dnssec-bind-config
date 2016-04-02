#!/usr/bin/python

##############################################################################################
# update-dnssec-bind-config
# 
# Generate bind zone files from templates and sign DNSSEC enabled zones. Also 
# creates SMIMEA records and includes TLSA records. Can push modified configs 
# via SCP to remote servers.
# 
# Copyright (C) 2016 John Bieling
#
# Available at:
# https://github.com/jobisoft/update-dnssec-bind-config
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################################

#ToDo
# - support views
# - delete removed zones from generated folder
# - check if all dns server have the same SERIAL if no updates to be send

# needs dnspython package
import socket, ConfigParser, os, sys, dns.zone, dns.resolver, time, subprocess, getopt, base64, hashlib
from dns.exception import DNSException
from M2Crypto import X509, SSL
from binascii import b2a_hex


def usage():
	print ""   
	print "This script will generate bind zone files and the bind config"
	print "for local zones (<namend.conf.local> based on the current"
	print "template/config files.\n"

	print "The main config file (update_dnssec_bind_config.ini) is"
	print "read from the current working directory, the script will fail if"
	print "it is not found. All path within that config (if not absolute)"
	print "are relative to the current working directory.\n"
	
	print "More information can be found in the README.\n"

	print "Usage: " + sys.argv[0] + " [option]\n"
	print "Allowed options (only one at a time):"
	print "\n\t -h \t --help   : Print this screen."
	print "\n\t -u \t --update : Look for changed zone templates and \n\t\t\t    re-generate zone files and local bind \n\t\t\t    config if needed."
	print "\n\t -f \t --force  : Force re-generation of zone config \n\t\t\t    file and all zone files."
	print ""

	sys.exit(1)



def getFilesInDirectory(dir, FailOnError = True):
	if os.path.exists(dir):
		return next(os.walk(dir))[2]
	elif not FailOnError:
		return False
	else:
		print "Folder <"+dir +"> does not exist. Aborting."
		sys.exit(1)

def getConfigEntry(section,option,config, optional = 0):
	try:
		value = config.get(section,option)
	except:
		if not optional:
			print "Failed to get " + option + " option from " + section + " section."
			sys.exit(1)
		else:
			return ""
	return value

def extractStartStop(startString, endString , filestr):
	start = filestr.find(startString)
	end = filestr.find(endString, start)
	if start == -1 or end == -1 or start > end:
		return ""
	return filestr[start+len(startString):end].strip('\n\r ')

def checkFolder(folder):
	if not folder.startswith("/"):
		folder = os.getcwd() + "/" + folder
	if not folder.endswith("/"):
		folder = folder + "/"
	if not os.path.exists(folder):
			os.makedirs(folder)
	return folder

def isIP(s):
	a = s.split('.')
	if len(a) != 4:
		return False
	for x in a:
		if not x.isdigit():
			return False
		i = int(x)
		if i < 0 or i > 255:
			return False
	return True

def getHash(certificate, mtype):
	# Based on https://github.com/pieterlexis/swede/blob/master/swede
	# Hashes the certificate based on the mtype.
	# The certificate should be an M2Crypto.X509.X509 object (or the result of the get_pubkey() function on said object)

	certificate = certificate.as_der()
	if mtype == 0:
		return b2a_hex(certificate)
	elif mtype == 1:
		return hashlib.sha256(certificate).hexdigest()
	elif mtype == 2:
		return hashlib.sha512(certificate).hexdigest()
	else:
		raise Exception('TLSA mtype should be 0,1,2')

def getSmimeaRecord(folder, pemfilename):
	# mode 300 is used for smimea (host and not ca, full and not just public subject, full cert, not just hash
	usage = 3

	certificate = X509.load_cert(folder + pemfilename)
	if not certificate:
		raise Exception('Cannot load certificate from disk')

	(localpart, domain) = pemfilename.split("@",1)
	data = b2a_hex(certificate.as_der())
	c = len(data)/2

	#https://tools.ietf.org/pdf/draft-ietf-dane-smime-10.pdf
	smimea = hashlib.sha256(localpart).hexdigest()[:28*2] + "._smimecert." + domain+ ". IN TYPE53 \# %i ( 0%i 00 00 %s )" % (c + 3, usage, data)
	return smimea

def getZoneFile(zoneName, useWritePath = 0):
	base = GeneratedZoneFolder
	if useWritePath:
		base = GeneratedZoneFolderWriteInConf

	return base + zoneName

def extractTemplate(templatetype , filestr):
	startString = "### " + templatetype + " START ###";
	endString = "### " + templatetype + " END ###";
	return extractStartStop(startString, endString, filestr)

def getOptionsDict(str):
	options = {}
	for line in str.splitlines():
		(key, value) = line.split(" ",1)
		#check if ";" is present
		value = value.strip()
		if not value.endswith(";"):
			value += ";"
		options[key.lower()] = value.lower()
	return options

def readSoaTemplate(filename):
	with open (filename, 'r') as myfile:
		filestr = myfile.read()

		data = {}
		data["LastModificationDate"] = os.path.getmtime(filename)
		data["RecourceRecords"] = extractTemplate("SOA RECORD" ,filestr)
		data["Definitions"] = extractTemplate("DEFINITIONS" ,filestr)
		data["Options"] = getOptionsDict(extractTemplate("OPTIONS" , filestr))

		# do not allow custom type options
		data["Options"].pop("type", None)
		return data

def readZoneTemplate(filename):
	with open (filename, 'r') as myfile:
		filestr = myfile.read()

		data = {}
		data["SoaRecordTemplate"] = extractStartStop("### SOA:"," ###", filestr)
		data["RecourceRecords"] = extractTemplate("RECORDS" ,filestr)
		data["Options"] = {}
		data["Options"].update(soaData[data["SoaRecordTemplate"]]["Options"]) 
		data["Options"].update(getOptionsDict(extractTemplate("OPTIONS" , filestr)))

		# do not allow custom type options
		data["Options"].pop("type", None)
		return data

def getCurrentSerial(zoneName):
	try:
		zone = dns.zone.from_file(getZoneFile(zoneName), zoneName)
	except:
		return "0000000000"
	for (name, ttl, rdata) in zone.iterate_rdatas(dns.rdatatype.SOA):
		try:
			serial = str(rdata.serial) +  "0000000000";
		except:
			serial = "0000000000";
	return serial[0:10]

def getNextSerial(zoneName):
	serial = getCurrentSerial(zoneName)
	serial_date = str(serial[0:8])
	serial_count = str(serial[8:10])
	today_date = time.strftime('%Y%m%d') 
	if today_date == serial_date:
		new_serial = str(int(serial_date + serial_count) + 1)
	else:
		new_serial = today_date + "01"
	return new_serial

def getResourceRecords(zoneName):
	rr = zoneData[zoneName]["RecourceRecords"]
	for definition in soaData[zoneData[zoneName]["SoaRecordTemplate"]]["Definitions"].splitlines():
		(name, ip) = definition.split(" ")
		rr = rr.replace(name,ip)
	return rr

def generateZone(zoneName):
	newSerialNr = getNextSerial(zoneName)
	newZoneFile = "; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"
	newZoneFile += "; * DO NOT EDIT THIS FILE, IT IS GENERATED AND WILL BE OVERWRITTEN! *\n"
	newZoneFile += "; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n\n"
	newZoneFile += soaData[zoneData[zoneName]["SoaRecordTemplate"]]["RecourceRecords"].replace("##SERIAL##", newSerialNr , 1) + "\n\n" 
	newZoneFile += getResourceRecords(zoneName) + "\n"  

	with open(getZoneFile(zoneName), 'w') as file:
		os.chmod(getZoneFile(zoneName),0o644)
		file.write(newZoneFile)

	if os.path.isdir(KeyFolder + zoneName):
		ZonesignerCmd = ZonesignerPath + " " + ZonesignerOptions + " -zone " + zoneName + " " + getZoneFile(zoneName) + " " + getZoneFile(zoneName)  + ".signed"
		print "-> Calling zonesigner: " + ZonesignerCmd 

		# Call zonesigner
		p = subprocess.Popen(ZonesignerCmd, cwd=KeyFolder + zoneName, shell=True)
		p.wait()
		os.rename(getZoneFile(zoneName)  + ".signed", getZoneFile(zoneName))

	print "-> Zone <" + zoneName + "> has been generated with serial <" + newSerialNr + ">.\n"


def zoneIsSoonToExpire(zoneName):
	if os.path.isdir(KeyFolder + zoneName):
		zone = dns.zone.from_file(getZoneFile(zoneName), zoneName)
		now = time.gmtime()
	
		for name, node in zone.nodes.items():
			rdatasets = node.rdatasets
			for rdataset in rdatasets:
				f = str(rdataset).split(" ")
				if f[1].upper() == "IN" and f[2].upper() == "RRSIG" and f[3].upper() == "SOA":
					expire = time.strptime(f[7], '%Y%m%d%H%M%S')
					days = int((time.mktime(expire) - time.mktime(now))/(60*60*24))
					if days < 5:
						return 1
					else:
						return 0

	return 0



##############################################################################################
## main ######################################################################################
##############################################################################################



try:
	opts, args = getopt.getopt(sys.argv[1:], "uf", ["update","force"])
except getopt.GetoptError:   
	usage()

if not len(opts) == 1:
	usage()

GenerationIsEnforced = False
if opts[0][0] in ("-u","--update"):
	GenerationIsEnforced = False
elif opts[0][0] in ("-f", "--force"):
	GenerationIsEnforced = True
else:
	usage()



# Read ConfigFile
Config = ConfigParser.SafeConfigParser()
ConfigPath = 'update-dnssec-bind-config.ini'

# Does the config file exist?
if not os.path.exists(ConfigPath):
	print "Failed to open config file: %s." % (ConfigPath)
	exit(1)

# Can we read it?
try:
	Config.read(ConfigPath)
except:
	print "Failed to read/parse config file: %s." % (ConfigPath)
	exit(1)

# Get all the options.
TemplateFolder = getConfigEntry('GlobalConfig', 'TemplateFolder', Config)
GeneratedZoneFolder = getConfigEntry('GlobalConfig', 'GeneratedZoneFolder', Config)
GeneratedZoneFolderWriteInConf = getConfigEntry('GlobalConfig', 'GeneratedZoneFolderWriteInConf', Config)
NamedConfPath = getConfigEntry('GlobalConfig', 'named.conf.local', Config)

ZonesignerPath = getConfigEntry('DNSSEC', 'ZonesignerPath', Config)
ZonesignerOptions = getConfigEntry('DNSSEC', 'ZonesignerOptions', Config)
KeyFolder = getConfigEntry('DNSSEC', 'KeyFolder', Config)

SMIMECertsFolder = getConfigEntry('SMIMEA', 'CertsFolder', Config)
SMIMECertsUpdateCmd = getConfigEntry('SMIMEA', 'UpdateCmd', Config, optional = 1)

TLSARecordsFolder  = getConfigEntry('TLSA', 'RecordsFolder', Config)
TLSARecordsUpdateCmd = getConfigEntry('TLSA', 'UpdateCmd', Config, optional = 1)

# Get optional server push commands.
try:
	RemoteUpdates = dict(Config.items('RemoteUpdates'))
except:
	RemoteUpdates = dict()



# Check folder path for trailing slash and create path, if it does not exist.
TemplateFolder = checkFolder(TemplateFolder)
SoaFolder = checkFolder(TemplateFolder + "SOA")
ZonesFolder = checkFolder(TemplateFolder + "ZONES")
GeneratedZoneFolder = checkFolder(GeneratedZoneFolder)
GeneratedZoneFolderWriteInConf = checkFolder(GeneratedZoneFolderWriteInConf)
KeyFolder = checkFolder(KeyFolder)
TLSARecordsFolder = checkFolder(TLSARecordsFolder)
SMIMECertsFolder = checkFolder(SMIMECertsFolder)

# Make the generated zone file folder world readable, so we
# do not run into permission problems
os.chmod(GeneratedZoneFolder,0o755)


# Init
configChanged = GenerationIsEnforced
soaData = {}
zoneData = {}

# Update SMIME and TLSA if requested.
if SMIMECertsUpdateCmd:
	p = subprocess.Popen(SMIMECertsUpdateCmd, shell=True)
	p.wait()
if TLSARecordsUpdateCmd:
	p = subprocess.Popen(TLSARecordsUpdateCmd, shell=True)
	p.wait()

# For each file in SoaFolder extract data.
soaFiles = getFilesInDirectory(SoaFolder)
for soaFile in soaFiles:
	soaData[soaFile] = readSoaTemplate(SoaFolder + soaFile)

# Regenerate zone files from template data, if templates last modification
# date ist greater then the generated one.
templateZoneFiles = getFilesInDirectory(ZonesFolder)
for zoneName in templateZoneFiles:
	zoneData[zoneName] = readZoneTemplate(ZonesFolder + zoneName)

	# Get last modification date of template
	tLMD = os.path.getmtime(ZonesFolder + zoneName)

	# Get LastModificationDate of generated file.
	try:
		gLMD = os.path.getmtime(getZoneFile(zoneName))
	except OSError:
		gLMD  = 0

	# Check DNSSEC zone expire and force regen/resign by setting gLMD to one
	if gLMD and zoneIsSoonToExpire(zoneName):
		gLMD = 1

	# Get external TLSA records.
	tlsaFiles = getFilesInDirectory(TLSARecordsFolder)
	for tlsaFile in tlsaFiles:
		if tlsaFile.endswith(zoneName):
			with open(TLSARecordsFolder + tlsaFile, 'r') as myfile:
				zoneData[zoneName]["RecourceRecords"] = zoneData[zoneName]["RecourceRecords"] + "\n" + myfile.read().strip() + "\n"
				# Project last modification date of tlsa file onto template.
				tLMD = max(tLMD, os.path.getmtime(TLSARecordsFolder + tlsaFile))

	# Get SMIMEA records for SMIME certificates.
	smimeFiles = getFilesInDirectory(SMIMECertsFolder)
	for smimeFile in smimeFiles:
		if smimeFile.endswith(zoneName):
			smimea = getSmimeaRecord(SMIMECertsFolder, smimeFile)
			if smimea: 
				zoneData[zoneName]["RecourceRecords"] = zoneData[zoneName]["RecourceRecords"] + "\n" + smimea + "\n"
				# Project last modification date of smime file onto template.
				tLMD = max(tLMD, os.path.getmtime(SMIMECertsFolder + smimeFile))

	if tLMD > gLMD or soaData[zoneData[zoneName]["SoaRecordTemplate"]]["LastModificationDate"] > gLMD or GenerationIsEnforced:
		if GenerationIsEnforced:
			print "=> Zone <" + zoneName + "> is forced to be (re)generated.";
		elif gLMD == 0:
			print "=> Zone <" + zoneName + "> has been added and needs to be generated.";
		elif gLMD == 1:
			print "=> Zone <" + zoneName + "> is about to expire and needs to be resigned.";
		else:
			print "=> Zone <" + zoneName + "> has been modified and needs to be regenerated.";
		generateZone(zoneName)
		configChanged = True  



# Regenerate bind zones config file
curNamedConf = "invalid"
if os.path.exists(NamedConfPath) and not configChanged:
	with open(NamedConfPath, 'r') as myfile:
		lines = myfile.readlines()
		curNamedConf = ""
		# remove the first two line, which is generated on comment
		for line in lines[2:]:
			curNamedConf = curNamedConf + line

# Add active zones.
newNamedConf = ""
for zoneName in zoneData:
	newNamedConf  += 'zone "' + zoneName + '" {\n'
	newNamedConf  += '  type master;\n'
	for oKey, oValue in zoneData[zoneName]["Options"].iteritems():
		newNamedConf  += '  ' + oKey + ' ' + oValue + '\n'
	newNamedConf  += '  file "' + getZoneFile(zoneName, useWritePath = 1) + '";\n'
	newNamedConf  += '};\n\n'  

# Did the zones config change?
if not curNamedConf == newNamedConf:
	newNamedConf = "# Generated " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n" + newNamedConf
	with open(NamedConfPath, 'w') as file:
		os.chmod(NamedConfPath,0o644)
		file.write(newNamedConf)
	print "-> Regenerated zone config file <" + NamedConfPath+ ">."
	configChanged = True




# Push config to remote serves, if something changed
if configChanged:
	for server in RemoteUpdates:
		print "=> Updating server <" + server + ">"
		p = subprocess.Popen(RemoteUpdates[server], shell=True)
		p.wait()


	print "-> Waiting 10s for remote servers to update their config ..."
	time.sleep(10)
	print "-> Verifying remote configurations ..."


	
# Monitor configs on remote servers
remoteError = 0
for zoneName in zoneData:
	localSerial = getCurrentSerial(zoneName)
	for server in RemoteUpdates:
		if not isIP(server):
			print "** Cannot check serial of remote DNS server <"+server+">. Please provide valid IP in config."
			continue
		
		query = dns.resolver.Resolver()
		query.nameservers = [server]		
		try:
			answers = query.query( zoneName , "SOA" )
		except  dns.exception.DNSException:
			print "** DNS query for SOA of <" + zoneName + "> on <" + server + "> failed." 
			continue
			
		remoteSerial = "unknown"		
		if len(answers)>0:
			remoteSerial = str(answers[0].serial)
			
		if not localSerial == remoteSerial:
			print "** Serial missmatch: local " + localSerial + " vs " + remoteSerial + " " + str(server +  "        ")[:16]  + " [" + zoneName + "]"