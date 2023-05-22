
# DATABASE SINGLETON

import json, os, sys

#import mysql.connector

Database = {}
db_filename = "database.json"

#DBHOST = "localhost"	#127.0.0.1
#DBUSER = "Netadmin"
#DBPASS = "Clytemnestra37_"
#DBNAME = "netadmin"
#DBFILE = "database.json"

#class DB( object ):

#	db = None

#	def __new__(cls):
#		print( "DB.NEW" );
#		if not hasattr(cls, 'instance'):
#			cls.instance = super( Database, cls).__new__(cls)
#		return cls.instance
		
#	def __init__( self ):
#		print( "DB.INIT" );
#		self.db = mysql.connector.connect(
#			host = DBHOST,
#			user = DBUSER,
#			password = DBPASS,
#			database = DBNAME
#			)

#	def query( self, statement, values ):
#		cursor = self.db.cursor()
#		cursor.execute( statement, values )
#		result = cursor.fetchall()
#		return result
#
#	def queryone( self, statement, values ):
#		cursor = self.db.cursor()
#		cursor.execute( statement, values )
#		result = cursor.fetchone()
#		return result

def initialise( filename ):
	global Database
	db_filename = filename
	if not os.path.isfile(filename):
		print( "- Creating new datafile" )
		#Database = {}
		save()
	try:
		print( "- Loading datafile" )
		with open( filename ) as f:
			Database = json.load(f)
		#print( json.dumps( Database, indent=2))
	except Exception as e:
		print( "Invalid datafile: '"+filename+"'\n "+str(e) )	

def getUserByUsername( username ):
	if "auth" not in Database: return None
	if "records" not in Database["auth"]: return None
	if "index.username" not in Database["auth"]: return None
	if username not in Database["auth"]["index.username"]: return None

	userid = Database["auth"]["index.username"][username]
	return Database["auth"]["records"][str(userid)]

def getUserById( userid ):
	if "auth" not in Database: return {}
	if "records" not in Database["auth"]: return {}
	if userid not in Database["auth"]["records"]: return {}

	return Database["auth"]["records"][str(userid)]

def getNodes():
	if "nodes" not in Database: return {}
	if "records" not in Database["nodes"]: return {}
	
	return Database["nodes"]["records"]

# RETURNS: JSON
def getNodeById( id ):
	try:
		return Database["nodes"]["records"][str(id)]
	except Exception as e:
		#print("- failed to get node "+str(id))
		#sys.stdout.flush()
		return None
	#id = str(id)
	#print("- getting id "+str(id))
	#sys.stdout.flush()
	#if "nodes" not in Database: return {}
	#print("a")
	#sys.stdout.flush()
	#if "records" not in Database["nodes"]: return {}
	#print("b")
	#print( json.dumps( Database["nodes"]["records"]["1"] ))
	#sys.stdout.flush()
	#if id not in Database["nodes"]["records"]: return {}
	#print("C")
	#sys.stdout.flush()
	#return Database["nodes"]["records"][id]

def insertNode( hostname, ipaddr ):
	global Database
	if "nodes" not in Database: Database["nodes"]={}
	if "counter" not in Database["nodes"]: Database["nodes"]["counter"] = 0
	if "records" not in Database["nodes"]: Database["nodes"]["records"] = {}
	if "index.hostname" not in Database["nodes"]: Database["nodes"]["index.hostname"] = {}
	if "index.ipaddr" not in Database["nodes"]: Database["nodes"]["index.ipaddr"] = {}

	id = 0
	
	if hostname in Database["nodes"]["index.hostname"]:
		id = Database["nodes"]["index.hostname"][hostname]
		print( "Updating "+hostname+" ["+str(id)+"]")
		## UPDATE USER
		Database["nodes"]["records"][str(id)]["hostname"] = hostname
		Database["nodes"]["records"][str(id)]["ipaddr"] = ipaddr

	else:
		## NEW USER
		id = Database["nodes"]["counter"] + 1
		Database["nodes"]["counter"] = id
		print( "Adding "+hostname+ " with id "+str(id) )
	
		Database["nodes"]["records"][id] = {
			"id":id,
			"hostname":hostname,
			"ipaddr":ipaddr
		}
		Database["nodes"]["index.hostname"][hostname] = id
		Database["nodes"]["index.ipaddr"][ipaddr] = id
		
	save()
	return id

def save():
	with open( db_filename, 'w', encoding='utf-8') as f:
		json.dump( Database, f, ensure_ascii=False, indent=4 )

# Add or Update a user account password
def addUpdateUser( username, hash, salt ):
	global Database

	#print( json.dumps( Database, indent=2))

	if "auth" not in Database: Database["auth"]={}
	if "counter" not in Database["auth"]: Database["auth"]["counter"] = 0
	if "records" not in Database["auth"]: Database["auth"]["records"] = {}
	if "index.username" not in Database["auth"]: Database["auth"]["index.username"] = {}

	userid=0

	if username in Database["auth"]["index.username"]:
		userid = Database["auth"]["index.username"][username]
		print( "Updating "+username+" ["+str(userid)+"]")
		## UPDATE USER
		Database["auth"]["records"][str(userid)]["password_hash"] = hash
		Database["auth"]["records"][str(userid)]["password_salt"] = salt

	else:
		## NEW USER
		userid = Database["auth"]["counter"] + 1
		Database["auth"]["counter"] = userid
		print( "Adding "+username+ " with id "+str(userid) )
	
		Database["auth"]["records"][userid] = {
			"id":userid,
			"username":username,
			"password_hash":hash,
			"password_salt":salt
		}
		Database["auth"]["index.username"][username] = userid

	save()
	return userid

def getRecordById( table, id, fields ):
	try:
		result = {}
		for field in fields:
			result[field] = Database[table]["records"][str(id)][field]
		return result
	except Exception as e:
		print( str(e) )
	finally:
		pass