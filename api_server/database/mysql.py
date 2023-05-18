
# DATABASE SINGLETON

import mysql.connector

DBHOST = "localhost"	#127.0.0.1
DBUSER = "Netadmin"
DBPASS = "Clytemnestra37_"
DBNAME = "netadmin"

class Database( object ):

	db = None

	def __new__(cls):
		print( "DB.NEW" );
		if not hasattr(cls, 'instance'):
			cls.instance = super( Database, cls).__new__(cls)
		return cls.instance
		
	def __init__( self ):
		print( "DB.INIT" );
		self.db = mysql.connector.connect(
			host = DBHOST,
			user = DBUSER,
			password = DBPASS,
			database = DBNAME
			)

	def query( self, statement, values ):
		cursor = self.db.cursor()
		cursor.execute( statement, values )
		result = cursor.fetchall()
		return result

	def queryone( self, statement, values ):
		cursor = self.db.cursor()
		cursor.execute( statement, values )
		result = cursor.fetchone()
		return result
		
def db_read(query, params=None):
	try:
		cursor = db.cursor( dictionary=True, buffered=True )
		if params:
			cursor.execute(query, params)
		else:
			cursor.execute(query)
		entries = cursor.fetchall()
		cursor.close()
		content = []
		for entry in entries:
			content.append(entry)
		return content
	except Exception as e:
		Write( "db_read() FAILED\nEXCEPTION: "+str(e)+"\n  "+str(query).replace("\n","\n  ")+"\n+PARAMS: "+str(params), "ERROR" )
		
def db_write(query, params):
	cursor = db.cursor()
	try:
		cursor.execute(query, params)
		db.commit()
		cursor.close()
		return True
	except MySQLdb._exceptions.IntegrityError:
		Write( "db_write() FAILED\n  "+str(query).replace("\n","\n  ")+"\n+PARAMS: "+str(params), "ERROR" )
		cursor.close()
		return False
	except Exception as e:
		Write( "db_write() FAILED\nEXCEPTION: "+str(e)+"\n  "+str(query).replace("\n","\n  ")+"\n+PARAMS: "+str(params), "ERROR" )
		cursor.close()
		return False

def initialise( config ):
	DBHOST = config.get( 'database', 'host', fallback="127.0.0.1" )
	DBUSER = config.get( 'db.netadmin', 'user', fallback="USERNAME" )
	DBPASS = config.get( 'db.netadmin', 'pass', fallback="PASSWORD" )
	DBNAME = config.get( 'db.netadmin', 'name', fallback="demo" )
	JWT_SECRET_KEY = config.get( 'authentication', 'JWT_SECRET_KEY', fallback=os.urandom(16).hex() )

	try:
		db = mysql.connector.connect(
		host = DBHOST,
		user = DBUSER,
		password = DBPASS,
		database = DBNAME
		)
		Write( "Database open" )
	except Exception as e:
		Write( "Failed to connect to database: "+str(e), "ERROR" )
		print( "Failed to connect to database: "+str(e) )
		sys.exit()	
	dblock = threading.Lock()


def getUserByEmail( email ):
	return db_read( """SELECT * FROM auth WHERE email=%s""", (email,))

def getDeviceByID( id ):
	SQL = """
		SELECT id,hostname,ipaddress,class,location,icon,status
		FROM devices
		WHERE id=%s;
	"""
	#
	dblock.acquire()
	#
	cursor = db.cursor( dictionary=True, buffered=True )
	cursor.execute( SQL, (id,) )
	records = cursor.fetchall()
	count = cursor.rowcount
	db.commit()
	cursor.close()
	#
	dblock.release()
	#
	print( records )
	return( json.dumps(records) )

def addUser( username, hash, salt ):
	SQL = """
		INSERT INTO auth( email, password_hash, password_salt )
		VALUES( %s,%s,%s );
	"""
	#
	dblock.acquire()
	#
	cursor = db.cursor( dictionary=True, buffered=True )
	cursor.execute( SQL, (username,hash,salt) )
	db.commit()
	cursor.close()
	#
	dblock.release()
