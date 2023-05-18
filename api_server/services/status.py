
import datetime

from flask import request
from flask_restful import Resource

#from bin.webservice import WebService
from bin.database import Database

class DeviceStatus( Resource ):

	#db = None

	def __init__( self ):
		self.db = Database()
	
	def get( self ):
		print( "GETTING" )

		if "since" in request.args:
			timestamp = int( request.args.get("since") )
			#timestamp = datetime.datetime.fromtimestamp( timestamp )
			#timestamp = timestamp.timestamp()
			result = self.db.query( "SELECT id,icmp,updated FROM devices WHERE updated>=%s",  [timestamp] )
			#device = {}
			#device["id"] = result[0]
			#device["status"] = result[1]
			#device["updated"] = result[2].timestamp()
			#return { "data": device }, 200
		else:
			result = self.db.query( "SELECT id,icmp,updated FROM devices", [] )

		print( "GOT RESULTS" )
		print( result )
		data = []		
		for row in result:
			print( row )
			device = {}
			device["id"] = row[0]
			device["status"] = row[1]
			device["updated"] = row[2].timestamp()
			data.append( device )
		return { "data": data }, 200
		
		#print( result )
		
		#return {"error":"" }, 404
		
