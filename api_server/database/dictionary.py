
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
	db_filename = filename
	if not os.path.isfile(filename):
		print( "Datafile does not exist - Creating empty one " )
		#Database = json.loads('{"auth":{},"devices":{}}')
		save()
	try:
		with open( filename ) as f:
			Database = json.load(f)
	except Exception as e:
		print( "Invalid datafile: '"+filename+"'\n "+str(e) )	

def getUserByEmail( email ):
	if auth not in Database: return {}
	for user in Database["auth"]:
		if user["email"]==email: return user
	return {}

def getDeviceById( id ):
	if devices not in Database: return {}
	if id not in Database["devices"]: return {}
	return Database["devices"][id]

def save():
	with open( db_filename, 'w', encoding='utf-8') as f:
		json.dump( Database, f, ensure_ascii=False, indent=4 )

def addUser( username, hash, salt ):
	user = {
		"id":0,
		"email":username,
		"password_hash":hash,
		"password_salt":salt
	}

	# Increment ID counter
	if not "auth_incremental" in Database:
		user["id"] = 1
	else:
		user["id"] = Database["auth_incremental"] + 1
	Database["auth_incremental"] = user["id"]

	if not "auth" in Database: Database["auth"]={}
	
	Database["auth"][user["id"]]=user
	save()
