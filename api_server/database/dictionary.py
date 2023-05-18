
# DATABASE SINGLETON

import json, os

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
		print( "Datafile does not exist - Creating empty one " )
		#Database = {}
		save()
	try:
		print( "Loading datafile" )
		with open( filename ) as f:
			Database = json.load(f)
		print( json.dumps( Database, indent=2))
	except Exception as e:
		print( "Invalid datafile: '"+filename+"'\n "+str(e) )	

def getUserByEmail( email ):
	if "auth" not in Database: return {}
	if "records" not in Database["auth"]: return {}
	if "index.email" not in Database["auth"]: return {}
	if email not in Database["auth"]["index.email"]: return {}

	userid = Database["auth"]["index.email"][email]
	return Database["auth"]["records"][userid]

def getUserById( userid ):
	if "auth" not in Database: return {}
	if "records" not in Database["auth"]: return {}
	if userid not in Database["auth"]["records"]: return {}

	return Database["auth"]["records"][userid]

def getDeviceById( id ):
	if "devices" not in Database: return {}
	if id not in Database["devices"]["records"]: return {}
	return Database["devices"]["records"][id]

def save():
	with open( db_filename, 'w', encoding='utf-8') as f:
		json.dump( Database, f, ensure_ascii=False, indent=4 )

def addUpdateUser( username, hash, salt ):
	global Database

	print( json.dumps( Database, indent=2))

	if not "auth" in Database:
		Database["auth"]={
			"counter":0,
			"records":{},
			"index.email":{}
		}
	if "counter" not in Database["auth"]: Database["auth"]["counter"] = 0
	if "records" not in Database["auth"]: Database["auth"]["records"] = {}
	if "index.email" not in Database["auth"]: Database["auth"]["index.email"] = {}

	userid=0

	if username in Database["auth"]["index.email"]:
		userid = Database["auth"]["index.email"][username]
		print( "Updating "+username+" with id="+str(userid))
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
			"email":username,
			"password_hash":hash,
			"password_salt":salt
		}
		Database["auth"]["index.email"][username] = userid

	save()
	return userid
