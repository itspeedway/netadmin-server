# NetadminAPI
# (c) Copyright Si Dunford, Jun 2020 to date

import configparser, json, os, sys, threading, logging
#import mysql.connector
#import logging
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

from flask import Flask, request, Response, jsonify, make_response
from datetime import datetime

from threading import Timer

from  werkzeug.security import generate_password_hash, check_password_hash
from hashlib import pbkdf2_hmac
import jwt

"""
FURTHER READING:

https://medium.com/@karthikeyan.ranasthala/build-a-jwt-based-authentication-rest-api-with-flask-and-mysql-5dc6d3d1cb82
https://roytuts.com/jwt-authentication-using-python-flask/
https://geekflare.com/securing-flask-api-with-jwt/
https://python.plainenglish.io/json-web-tokens-with-python-apis-5777f53f5543

https://auth0.com/blog/how-to-handle-jwt-in-python/

"""

#from flask_jwt import JWT, jwt_required, current_identity
#from werkzeug.security import generate_password_hash, check_password_hash

#	CONSTANTS / CONFIG

CONFIGFILE = "config.ini"
APPNAME = "netadmin-api-server"

#	
MQ=None
DB=None
JWT_Secret_Token=None

# This was an experiment and will not be used
#JSONRPC_Requests = {}

ERROR_PARSE_ERROR      = -32700 	# Invalid JSON was received by the server.
ERROR_INVALID_REQUEST  = -32600 	# The JSON sent is not a valid Request object.
ERROR_METHOD_NOT_FOUND = -32601 	# The method does not exist / is not available.
ERROR_INVALID_PARAMS   = -32602 	# Invalid method parameter(s).
ERROR_INTERNAL_ERROR   = -32603 	# Internal JSON-RPC error.

########## UTILITY FUNCTIONS ############################

def Write( message, severity="INFO" ):

	print( severity+": "+message, file=sys.stderr )
	#print('This is error output', file=sys.stderr)
	#print('This is standard output', file=sys.stdout)
	sys.stdout.flush()

	#with open( RUNLOG, "a" ) as myfile:
	#	myfile.write( severity+", "+message.replace(",",";")+"\n" )
		
	#now = datetime.now()
	#time = now.strftime( "%H:%M:%S" )

	#with open( LOGPATH+str( now.date() )+".log", "a" ) as file:
	#	file.write( str(time)+" - " + severity+" - "+str(message)+"\n" )
	if severity == "INFO":
		logging.info( message )
	elif severity=="DEBUG":
		logging.debug( message )
	elif severity=="WARNING":
		logging.warning( message )
	elif severity=="ERROR":
		logging.error( message )
	elif severity=="CRITICAL":
		logging.critical( message )
	else:
		logging.critical( "Unknown severity level: "+severity )
		logging.debug( message )

# Equivalent of Javascript setTimeout( delay, callback )
class setTimeout( Timer ):
	def run( self ):
		while not self.finished.wait( self.interval ):
			self.function( *self.args, **self.kwargs )
			
# Timeout keepalive
def keepalive():
	Write( "Keepalive", "DEBUG" )

########## MESSAGE QUEUE ###############

def on_connect( client ):
	Write( "MQ Connected" )
	topic = config.get( APPNAME, 'mq.topic', fallback="" )
	if topic=="": topic= "netadmin/api-server"

	MQ.lwt( topic, {"state":"down"} )			# Publish last will and testament
	MQ.publish( topic, {"state":"up"}, True )	# Publish current state (Retained)
	
def on_disconnect( client ):
	Write( "MQ Disconnected", "ERROR" )

def on_error( error ):
	Write( "MQ Error: "+str(error), "ERROR" )
	
def on_message( message ):
	Write( "Message received: "+str(message) )


# DECORATOR FOR JWT VERIFICATION
# https://www.geeksforgeeks.org/using-jwt-for-user-authentication-in-flask/
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated



# Update RUN.LOG
#def RunLog( errcode=0, message="NULL" ):
#	if errcode==2:
#		severity="WARN"
#	elif errcode==3:
#		severity="CRIT"
#	else:
#		severity="INFO"
#		
#	with open( RUNLOG, "a" ) as file:
#		file.write( severity+", "+message.replace(",",";")+"\n" )
	
	

		
#class Users(object):	
#	def __init__(self, id, username):
#		self.id = id
#		self.username = username
#
#	def __str__(self):
#		return "User(id='%s')" % self.id

########## CORS ########################

# CORS
def render_CORS_preflight( request, methods="GET,OPTIONS", message={} ):
	print( "render_CORS_preflight()" )
	
	# Create a new response
	json = jsonify( message )
	response = make_response( json )

	# ALLOW CREDENTIALS
	#response.headers.add('Access-Control-Allow-Credentials', "true" )

	# ALLOW HEADERS
	headers = [
		"Access-Control-Allow-Headers",
		"Access-Control-Request-Method",
		"Origin",
		"Authorization",
		"Accept",
		"X-Requested-With",
		"Content-type"
		]
	headers = ",".join(headers)
	Write( "HEADERS.ALLOW: "+str(headers) )
	response.headers['Access-Control-Allow-Headers'] = headers

	#header('Access-Control-Allow-Origin: *');
	#header('Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS');
	#header('Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token');

	# ALLOWED METHODS
	
	# Ensure OPTIONS is a valid method
	list = methods.upper().split(",")
	if not "OPTIONS" in list: list.append("OPTIONS")
	methods = ",".join( list )
	Write( "METHODS.ALLOW: "+str(methods) )
	#response.headers[ 'Access-Control-Allow-Methods' ] = methods
	response.headers[ 'Access-Control-Allow-Methods' ] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
	
	# ALLOW ORIGIN
	origin = request.remote_addr
	#origin = request.origin
	Write( "ORIGIN.ALLOW: "+str(origin) )
	print( "ORIGIN:       "+str( request.origin ) )
	#TODO: Check if origin is allowed here
	response.headers[ "Access-Control-Allow-Origin" ] = "*"
	#response.headers[ 'Access-Control-Allow-Origin' ] = origin 
	
	print( "RESPONSE:HEADERS" )
	print( str(response.headers) )
	
	return response

#def add_CORS_Header( response ):
#	response.headers.add( "Access-Control-Allow-Origin", "*" )
#	return response
	
# START ROUTING

#@app.get( "/" )
#def get_home():
#	Write( "Request to incomplete route: '/'", "DEBUG" )
	
########################################
########## AUTHENTICATION ##############

def generate_salt():
    salt = os.urandom(16)
    return salt.hex()

def generate_hash( plain_password, password_salt ):
    password_hash = pbkdf2_hmac(
        "sha256",
        b"%b" % bytes(plain_password, "utf-8"),
        b"%b" % bytes(password_salt, "utf-8"),
        10000,
    )
    return password_hash.hex()

def generate_jwt_token(content):
    
    encoded_content = jwt.encode(content, JWT_Secret_Token, algorithm="HS256")
    token = str(encoded_content).split("'")[1]
    return token

def validate_user(email, password):
	email = email.strip()
	password = password.strip()
	if email=="" or password=="": return (False,"Username and password cannot be blank",None)
	
	#current_user = db_read( """SELECT * FROM auth WHERE email=%s""", (email,))
	current_user = DB.getUserByEmail( email )

	Write( str( current_user ) )
	
	if len(current_user) == 1:
		saved_password_hash = current_user[0]["password_hash"]
		saved_password_salt = current_user[0]["password_salt"]
		if saved_password_hash==None or saved_password_salt==None: 
			return (False,"Invalid login",None)
		
		password_hash = generate_hash( password, saved_password_salt )

		if password_hash == saved_password_hash:
			user_id = current_user[0]["id"]
			jwt_token = generate_jwt_token({"id": user_id})
			return (True,"",jwt_token)
		else:
			return (False,"Invalid login",None)
	else:
		return (False,"Invalid login",None)

def validateJWT( request ):
	token = None
	# jwt is passed in the request header
	if 'x-access-token' in request.headers:
		token = request.headers['x-access-token']
	if not token: return (None,"Token is missing")

	try:
		# decoding the payload to fetch the stored details
		data = jwt.decode(token, JWT_Secret_Token )
		current_user = User.query\
			.filter_by(public_id = data['public_id'])\
			.first()
		return (current_user,None)
	except:
		return (None,"Token is invalid")	

class User:

	def query(*,email):
		SQL = "SELECT * FROM auth WHERE email=%s;"
		try:
			cursor = db.cursor( dictionary=True, buffered=True )
			cursor.execute( SQL, (email,) )
			entries = cursor.fetchall()
			cursor.close()
			return entries[0]
			content = []
			for entry in entries:
				content.append(entry)
			return content
		except Exception as e:
			Write(str(e))
			return None

#def makeRPC( id=None, method=None, params=None, error=None, result=None ):
#	jsonrpc = {
#		"jsonrpc":"2.0",
#	}
#	if id: jsonrpc["id"] = id
#	if method: jsonrpc["method"] = method
#	if params: jsonrpc["params"] = params
#	if result: jsonrpc["result"] = result
#	if error: jsonrpc["error"] = error
#	return jsonrpc
#
#	START API

#def makeRPCError( code, message, data=None ):
#	error = {
#		"code":code,
#		"message":message
#	}
#	if data: error["data"]=data
#	return error

########################################
########## FLASK API ###################

app = Flask(__name__)


# Handle 404 Page not found errors
@app.errorhandler(404)
def not_found(e):
	json = jsonify({
		"jsonrpc":"2.0",
		"error":{
			"code": "404",
			"message": "Page not found",
			"data": e
			}
		})
	response = make_response( json )
	return response

#	NETADMIN CAPABILITIES

#@app.route( "/netadmin", methods=["OPTIONS"] )
#def OPTIONS_jsonrpc():	# CORS
#	Write( "OPTIONS - /netadmin (JSONRPC)" )
#	return render_CORS_preflight( request, "POST" )

#@app.route( "/netadmin", methods=["POST"] )
#def POST_jsonrpc():
#	Write( "POST - /netadmin (JSONRPC)" )
#	if not request.json:
#		return make_response( "Unexpected data format", 401, {
#			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
#			})	
#	
#	Write( "- IT IS A JSON REQUEST" )
#	jsonrpc = request.json
#	if "jsonrpc" not in jsonrpc or jsonrpc["jsonrpc"] != "2.0":
#		return make_response( "Unexpected data format", 401, {
#			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
#			})
#	Write( "-It is a JSON RPC request" )
#
#	if "id" not in jsonrpc:
#		Write( "- Notificiation" )
#		# This is a notification / No response required
#		return '', 204
#
#	if "method" in jsonrpc:
#		# REQUEST
#		Write( "- REQUEST" )
#		method = jsonrpc["method"]
#		if method not in JSONRPC_Requests:
#			return make_response( 
#				jsonify(
#					makeRPC(
#						error=makeRPCerror(
#							id=jsonrpc["id"],
#							code=ERROR_METHOD_NOT_FOUND,
#							message="Method not found"
#							)
#					)
#				), 200)
#		# Call the method
#		JSONRPC_Requests[method]()
#	else:
#		# RESPONSE
#		# We dont expect to see these!
#		Write( "- RESPONSE" )
#		pass
#		
#	# Need to check authentication here
#	return make_response( jsonify({'test' : "hello world"}), 200)
#
#	return render_CORS_preflight( request, "POST" )

@app.route( "/netadmin", methods=["GET"] )
def GET_Capabilities():
	Write( "GET - /netadmin (Capabilities)" )
	data = {
		"capabilities":{
			"auth":{
				"url":"netadmin/auth"
			}
		}
	}
	return render_CORS_preflight( request, "GET", data )

#	NETADMIN AUTHENTICATION

@app.route( "/netadmin/auth", methods=["OPTIONS"] )
def OPTIONS_auth():	# CORS
	Write( "OPTIONS - /auth" )
	#log.info( "OPTIONS - /auth" )
	return render_CORS_preflight( request, "POST" )

@app.post( "/netadmin/auth" )
def POST_auth():
	Write( "POST - /auth" )
	#log.info( "POST - /auth" )

	#auth = request.form		# Turn form into a dictionary
	
	if not request.json:
		return make_response( "Unexpected data format", 401, {
			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
			})	
	
	Write( "IT IS A JSON REQUEST" )
	auth = request.json
	if "username" not in auth or "password" not in auth:
		return make_response( "Unexpected data format", 401, {
			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
			})	

	if auth["username"]==None or auth["password"]==None:
		return make_response( "Unable to verify", 401, {
			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
			})

	Write( "has username and password" )

	username  = auth["username"].strip()
	userpass  = auth["password"].strip()
	
	Write( "Username: "+str(username) )
	Write( "Password: "+str(userpass) )
	if username=="" or userpass=="":
		return make_response( "Unable to verify", 401, {
			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
			})
		
	user = User.query( email=username )
	Write( "USER: "+str(user) )
	if not user:
		return make_response( "Unable to verify", 401, {
			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
			})
	
	# Generate a password hash
	Write( "Checking hash" )
	saved_password_salt = user["password_salt"]
	saved_password_hash = user["password_hash"]
	if saved_password_salt==None or saved_password_hash==None:
		return make_response( "Unable to verify", 401, {
			'WWW-Authenticate' : 'Basic realm ="Invalid login"'
			})		
	
	password_hash = generate_hash( userpass, saved_password_salt )
	if password_hash == saved_password_hash:
		
		#if check_password_hash( user.password, userpass ):
        # generates the JWT Token
		token = jwt.encode({
			'userid': user["id"],
			'expires' : datetime.utcnow() + timedelta(minutes = 30)
		}, JWT_Secret_Token)

		return make_response( jsonify({'token' : token.decode('UTF-8')}), 201)
	
	Write( "Incorrect password" )
	# returns 403 if password is wrong
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Invalid login"'}
	)

	return render_CORS_preflight( request, "POST" )

# Login attempt (old)
@app.route( "/api/auth/login", methods=["OPTIONS"] )
def login_CORS():
	Write( "/api/auth/login,OPTIONS" )
	#yield( "Login attempt" )
	Write( "OPTIONS - login" )
	
	#if request.method == "OPTIONS":	# CORS Preflight check
	return render_CORS_preflight( request, "GET,POST" )

@app.post( "/api/auth/login" )
def user_login():
	Write( "User authentication" )
	
	#response = Response(render_template( "index.html" ))
	#response = add_CORS_Header( response )
	
	Write( str( request.json) )
	
	if request.json:
		Write( "ITS JSON" )
		if "username" in request.json and "password" in request.json:
			Write( "has username and password" )
	
			#if request.is_json: # and "username" in request.json and "password" in request.json:
			user_name  = request.json["username"]
			user_pass  = request.json["password"]
			(success,errortext,user_token) = validate_user( user_name, user_pass )

			if user_token:
				Write( "Login success" )
				return jsonify({"jwt_token": user_token})
			else:
				Write( "Login failure: "+errortext )
				return Response( errortext, status=401 )
	Write( "Returning Invalid JSON" )
	return jsonify({"error": "Invalid JSON received"}), 415

# Password Recovery / Change password
@app.post( "/api/auth/recover" )
def post_recover():
	Write( "POST - recover" )
	if request.is_json:
		pass
		
		user_email = request.json["email"]
		user_password = request.json["password"]
		user_confirm_password = request.json["confirm_password"]

		if user_password == user_confirm_password and validate_user_input(
			"authentication", email=user_email, password=user_password
		):
			password_salt = generate_salt()
			password_hash = generate_hash(user_password, password_salt)

			if db_write(
				"""INSERT INTO users (email, password_salt, password_hash) VALUES (%s, %s, %s)""",
				(user_email, password_salt, password_hash),
			):
				# Registration Successful
				return Response(status=201)
			else:
				# Registration Failed
				return Response(status=409)
		else:
			# Registration Failed
			return Response(status=400)
		
	return {"error": "Invalid JSON received"}, 415

# Add a user account
@app.post( "/api/auth" )
def post_user():
	if request.is_json:
		device = request.get_json()
		
		return device, 201
	return {"error": "Invalid JSON received"}, 415

# Delete a user account
@app.delete( "/api/auth/<id>" )
def delete_user():
	if request.is_json:
		device = request.get_json()
		
		return device, 201
	return {"error": "Invalid JSON received"}, 415


########################################
########## DEVICES #####################

# Get device list
@app.route( "/api/v1/devices", methods=["OPTIONS"] )
def devices_CORS():
	Write( "/api/v1/devices,OPTIONS" )
	print( "REQUEST: /api/v1/devices,OPTIONS" )
	
	debug_request( request )
	
	Write( "OPTIONS - devices" )
	return render_CORS_preflight( request, "GET" )	#"GET,POST" )

# Get device list
@app.get( "/api/v1/devices" )
def devices_GET():
	Write( "/api/v1/devices,GET" )
	print( "REQUEST: /api/v1/devices,GET" )

	debug_request( request )

	SQL = """
		SELECT D.id,D.hostname,D.ipaddress,D.icon as type,D.status,L.name as location
		FROM devices D
		LEFT JOIN locations L
		ON D.location = L.id;
	"""
	#
	dblock.acquire()
	#
	cursor = db.cursor( dictionary=True, buffered=True )
	cursor.execute( SQL )
	records = cursor.fetchall()
	count = cursor.rowcount
	db.commit()
	cursor.close()
	#
	dblock.release()

	data = {}
	# {"id": 41, "hostname": "LBB_BRO_LIB_RT01", "status": 0}
	for device in records:
		print( str(device) )
		data[ device[ "hostname" ] ] = { "id":device[ "id" ], "type":device["type"], "ipaddress":device["ipaddress"], "status":device[ "status" ], "location":device[ "location" ] }
	
	#print( str(data) )
	
	Write( "GET - devices" )
	return render_CORS_preflight( request, "GET", data )

# THIS IS DUE TO BE TIED TO "ADD DEVICE"
@app.post( "/api/v1/device" )
def device_POST():
	Write( "Post Device" )
	if request.is_json:
		device = request.get_json()

		#id       = request.json["id"]
		hostname = request.json["hostname"]
		ipaddr   = request.json["ipaddr"]

		SQL = """
			INSERT INTO devices(hostname,ipaddr) VALUES (%s, %s)
			"""
		if db_write( SQL, ( hostname, ipaddr) ):
			# Registration Successful
			return Response(status=201)
		else:
			# Registration Failed
			return Response(status=409)
	return {"error": "Invalid JSON received"}, 415

# Get all devices at a specific location
@app.get( "/api/devices/at/<location>" )
#@token_required
def get_devices_in(location):
	Write( "GET - devices at location: "+location )
	SQL = """
		SELECT id,hostname,status
		FROM devices
		WHERE location=%s
		ORDER BY hostname;
	"""
	#
	dblock.acquire()
	#
	cursor = db.cursor( dictionary=True, buffered=True )
	cursor.execute( SQL, (location,) )
	records = cursor.fetchall()
	count = cursor.rowcount
	db.commit()
	cursor.close()
	#
	dblock.release()
	#
	print( records )
	return( json.dumps(records) )

# Get all devices
@app.get( "/api/devices" )
#@jwt_required()
def get_devices():
	Write( "GET - devices" )
	SQL = """
		SELECT id,hostname
		FROM devices
		ORDER BY hostname;
	"""
	#
	dblock.acquire()
	#
	cursor = db.cursor( dictionary=True, buffered=True )
	cursor.execute( SQL )
	records = cursor.fetchall()
	count = cursor.rowcount
	db.commit()
	cursor.close()
	#
	dblock.release()
	#
	print( records )
	return( json.dumps(records) )
	
# Get a specific device
@app.get( "/netadmin/devices/<id>" )
#@jwt_required()
def get_device(id):
	Write( "GET - devices - "+str(id) )
	return DB.getDeviceByID( id )
	
########################################
########## PLACES ######################
	
@app.get( "/api/locations" )
#@jwt_required()
def get_locations():
	Write( "GET - locations" )
	SQL = """
		SELECT id,name
		FROM locations
		ORDER BY name;
	"""
	#
	dblock.acquire()
	#
	cursor = db.cursor( dictionary=True, buffered=True )
	cursor.execute( SQL )
	records = cursor.fetchall()
	count = cursor.rowcount
	db.commit()
	cursor.close()
	#
	dblock.release()
	#
	print( records )
	return( json.dumps(records) )
	
@app.post( "/api/devices" )
#@jwt_required()
def add_device():
	if request.is_json:
		device = request.get_json()
		
		return device, 201
	return {"error": "Invalid JSON received"}, 415

@app.post( "/api/search" )
#@jwt_required()
def search():
	if not request.is_json:
		return {"error": "Invalid JSON received"}, 415

	criteria = request.get_json()
	Write( str(criteria) )
	
	return {}, 201
		

########################################
########## AUTHENTICATION ##############

"""	
def authenticate(username, password):	
	if username and password:
		#conn = None;
		#cursor = None;
		dblock.acquire()
		try:
			#conn = mysql.connect()
			#cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor = db.cursor( dictionary=True )
			SQL = "SELECT id,name,level FROM auth WHERE email=%s AND password=%s;"
			cursor.execute( SQL, (username, password)
			row = cursor.fetchone()
			
			if row:
				if check_password_hash(row['password'], password):
					return User(row['id'], row['username'])
			else:
				return None
		except Exception as e:
			print(e)
		finally:
			cursor.close() 
			conn.close()
	return None

def identity(payload):
	if payload['identity']:
		conn = None;
		cursor = None;
		try:
			conn = mysql.connect()
			cursor = conn.cursor(pymysql.cursors.DictCursor)
			cursor.execute("SELECT id, username FROM user WHERE id=%s", payload['identity'])
			row = cursor.fetchone()
			
			if row:
				return (row['id'], row['username'])
			else:
				return None
		except Exception as e:
			print(e)
		finally:
			cursor.close() 
			conn.close()
	else:
		return None

jwt = JWT(app, authenticate, identity)
"""

########## JSON-RPC REQUESTS ##########
# This was an experiment and will not be used
#def Request_Auth():
#	Write( "Request_Auth() Called" )
#	pass

########################################

def debug_request( request ):
	print("REQUEST HEADERS:")
	print(request.headers)
	print("COOKIES:")
	print(request.cookies)
	print("DATA:")
	print(request.data)
	print("ARGS:")
	print(request.args)
	print("FORM:")
	print(request.form)
	print("ENDPOINT:")
	print(request.endpoint)
	print("METHOD:")
	print(request.method)
	print("REMOTE_ADDR:")
	print(request.remote_addr)


if __name__ == "__main__":

	#	SET UP RPC METHOD CALLS
	# This was an experiment and will not be used

	#JSONRPC_Requests = {
	#	"auth":Request_Auth
	#}

	#	CONFIG FILE

	print( "Opening configuration" )
	config = configparser.ConfigParser()
	config.read( CONFIGFILE )

	#	LOGGING

	logpath = config.get( APPNAME, 'log.path', fallback="" )
	if logpath=="": logpath="log/"
	if not logpath.endswith("/"): logpath :+ "/"

	logfile = logpath + APPNAME

	logpath = Path( logfile ).parent
	if not os.path.isdir( logpath ):
		print( "Creating log folder" )
		os.mkdir( logpath )
	#else:
	#	print( "Logpath "+str(logpath)+" exists")

	loglevel = logging.DEBUG 
	#loglevel = config.get( APPNAME, 'log.level', fallback="5" )

	log = logging.getLogger(__name__)
	log.setLevel( loglevel )

	handler = TimedRotatingFileHandler( logfile, when="midnight", interval=1 )
	handler.suffix = "%Y-%m-%d.log"

	formatter = logging.Formatter( '%(asctime)s - %(levelname)s - %(message)s' )
	formatter.datefmt='%H:%M:%S'
	handler.setFormatter( formatter )
	log.addHandler( handler )

	log.info( APPNAME + " Started" )

	#	DATABASE

	db = config.get( APPNAME, 'database', fallback="database.json" )
	if db=="mysql":
		pass
		#import database.mysql as DB
		#DB.initialise( config )
	else:
		if not db.endswith(".json"): db :+ ".json"
		import database.dictionary as DB
		DB.initialise( db )

	#	ADMINISTRATOR PASSWORD RESET
	print( "ARGUMENTS:" + str(len(sys.argv) ) )
	if len(sys.argv)==4 and sys.argv[1]=="--reset":
		Write( "Updating administrator account", "WARNING" )
		username=sys.argv[2]
		password=sys.argv[3]
		password_salt =generate_salt()
		password_hash = generate_hash( password, password_salt )
		id = DB.addUpdateUser( username, password_hash, password_salt )
		Write( "Updated '"+username+"' with id="+str(id), "WARNING" )
		sys.exit(0)

	sys.quit()

	#	SET UP JWT TOKEN

	#JWT_SECRET_KEY = os.urandom(16).hex()	# WARNING - WILL BE DIFFERENT EACH RUN
	JWT_Secret_Token = config.get( APPNAME, 'jwt.secret', fallback="" )
	if JWT_Secret_Token=="": JWT_Secret_Token = os.urandom(16).hex()

	#	MESSAGE QUEUE LIBRARY

	#mq = config.get( APPNAME, 'message.queue', fallback="mqnull" )
	mq = "mqnull"
	mq_host = config.get( APPNAME, 'mq.host', fallback="127.0.0.1" )
	mq_port = config.get( APPNAME, 'mq.port', fallback="" )

	if mq=="mqtt":
		pass
		#import bin.mqtt as MQ
		#if mq_port="": mqport="8083"
	elif mq=="mqpython":
		pass
		#sys.path.append('/MessageQueue/bin')
		#import mypy as MQ
		#if mq_port="": mqport="6001"
	else:
		import bin.mqnull as MQ
	
	MQ.on( "connect", on_connect )
	MQ.on( "disconnect", on_disconnect )
	MQ.on( "message", on_message )
	MQ.on( "error", on_error )
	MQ.name( APPNAME )
	MQ.connect( mq_host, mq_port )

	#	KEEPALIVE TIMER

	timer = setTimeout( 3600, keepalive ).start()
	
	#	RUN SERVER
	port  = config.get( APPNAME, 'port', fallback="4010" )
	debug = config.get( APPNAME, 'port', fallback="" ) != ""
	if debug: print( "DEBUG MODE" )
	app.run( host="0.0.0.0", port=port, debug=debug )

	#	CLEAN UP

	timer.cancel()
