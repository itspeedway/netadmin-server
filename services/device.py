
from flask import request
from flask_restful import Resource
#from flask_restful import reqparse

#from bin.webservice import WebService
from bin.database import Database

class Device( Resource ):

	#db = None

	def __init__( self ):
		self.db = Database()
	
	def get( self ):
		print( "GETTING" )

		if "id" in request.args:
			result = self.db.queryone( "SELECT id,hostname,ipaddress FROM devices WHERE id=%s",  [request.args.get("id")] )
		elif "name" in request.args:
			result = self.db.queryone( "SELECT id,hostname,ipaddress FROM devices WHERE hostname=%s", [request.args.get("name")] )
		elif "ip" in request.args:	
			result = self.db.queryone( "SELECT id,hostname,ipaddress FROM devices WHERE ipaddress=%s", [request.args.get("ip")] )
		else:
			result = None
		
		print( result )
		
		if result:
			data = []
		
			device = {}
			device["id"] = result[0]
			device["hostname"] = result[1]
			device["ipaddress"] = result[2]
			#data.append( device )
			#for x in result:
			#	print(x)
			#		data.append( { "hostname":device["hostname"], "ipaddress":device["ipaddress"] } )
			return { "data": device }, 200
			#return json.dumps( data ), 200
	
		return {"error":"" }, 404
		
		#data = pd.read_csv('users.csv')  # read local CSV
		#data = data.to_dict()  # convert dataframe to dict
		#return {'data': ""}, 200  # return data and 200 OK

	def post(self):
		parser = reqparse.RequestParser()  # initialize
		parser.add_argument('userId', required=True)  # add args
		parser.add_argument('name', required=True)
		parser.add_argument('city', required=True)
		args = parser.parse_args()  # parse arguments to dictionary

		# read our CSV
		data = pd.read_csv('users.csv')

		if args['userId'] in list(data['userId']):
			return {
				'message': f"'{args['userId']}' already exists."
				}, 409
		else:
			# create new dataframe containing new values
			new_data = pd.DataFrame({
			'userId': [args['userId']],
			'name': [args['name']],
			'city': [args['city']],
			'locations': [[]]
			})
			# add the newly provided values
			data = data.append(new_data, ignore_index=True)
			data.to_csv('users.csv', index=False)  # save back to CSV
			return {'data': data.to_dict()}, 200  # return data with 200 OK

	def put(self):
		parser = reqparse.RequestParser()  # initialize
		parser.add_argument('userId', required=True)  # add args
		parser.add_argument('location', required=True)
		args = parser.parse_args()  # parse arguments to dictionary

		# read our CSV
		data = pd.read_csv('users.csv')
        
		if args['userId'] in list(data['userId']):
			# evaluate strings of lists to lists !!! never put something like this in prod
			data['locations'] = data['locations'].apply(
				lambda x: ast.literal_eval(x)
			)
			# select our user
			user_data = data[data['userId'] == args['userId']]

			# update user's locations
			user_data['locations'] = user_data['locations'].values[0] \
				.append(args['location'])

			# save back to CSV
			data.to_csv('users.csv', index=False)
			# return data and 200 OK
			return {'data': data.to_dict()}, 200

		else:
			# otherwise the userId does not exist
			return {
				'message': f"'{args['userId']}' user not found."
			}, 404

	def delete(self):
		parser = reqparse.RequestParser()  # initialize
		parser.add_argument('userId', required=True)  # add userId arg
		args = parser.parse_args()  # parse arguments to dictionary

		# read our CSV
		data = pd.read_csv('users.csv')
        
		if args['userId'] in list(data['userId']):
			# remove data entry matching given userId
			data = data[data['userId'] != args['userId']]

			# save back to CSV
			data.to_csv('users.csv', index=False)
			# return data and 200 OK
			return {'data': data.to_dict()}, 200
		else:
			# otherwise we return 404 because userId does not exist
			return {
				'message': f"'{args['userId']}' user not found."
			}, 404
			
class Devices( Resource ):

	#db = None

	def __init__( self ):
		self.db = Database()
	
	def get( self ):
		result = self.db.query( "SELECT id,hostname,ipaddress FROM devices;" )
		
		if result:
			data = []
			for row in result:
				print(row)
				device = {}
				device["id"] = row[0]
				device["hostname"] = row[1]
				device["ipaddress"] = row[2]
				data.append( device )
			return { "data": data }, 200
		return {"error":"Failed"},404