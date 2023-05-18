
# DATABASE SINGLETON

import json, os

#import mysql.connector

Database = {}

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
	if not os.path.isfile(filename):
		print( "Datafile does not exist " )
		return
	try:
		with open( filename ) as f:
			database = json.load(f)
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