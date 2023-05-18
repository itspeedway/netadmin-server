WEBSERVICES

INSTALLATION:
Create folder:

	mkdir D:\Webservices
	cd /d D:\Webservices

* Copy scripts into D:\Webservices
* Ensure Python 3 is installed on the server

	python --version
	python3 --version

* Ensure server has internet access for the duration of the install.

Install Virtual Environment:

	cd /d D:\NetadminAPI
	python -m venv venv
	python -m pip install --upgrade pip
	
Install dependencies:
	(Requires internet access)

	cd /d D:\NetadminAPI
	venv\scripts\activate
	!! python -m pip install requests
	python -m pip install --upgrade pip
	python -m pip install --upgrade mysql-connector-python
	python -m pip install --upgrade flask
	python -m pip install --upgrade websocket
	python -m pip install --upgrade websocket-client
	!! python -m pip install --upgrade flask-cors
	

The first time you run this script you will be asked to save the server fingerprint; please say yes.

UPGRADE:
----------------------------------------
(Requires internet access)

	python -m pip install --upgrade pip
	pip install --upgrade git+https://github.com/CheckPointSW/cp_mgmt_api_python_sdk



DESIGN IDEALS
All of these web services should run in different threads
However, the port needs to be the same, so the listener needs to deal with the router.

REST API

	Methods:
		GET		Obtain a single record
		DELETE	Delete an individual record
		HEAD	Returns the same as GET, but without a payload
		OPTIONS	Not used (Apart from CORS where necessary)
		PATCH	Update an existing record
		POST	Create a record
		PUT		Replace an existing record

	Header:
		All requests expect an Authentication-Bearer token in the header
		
	Response:
		All responses must return a valid JSON payload if possible, even if it is a null object: {}
		Valid responses should contain:
	
			{
			"response":<CONTENT>
			}
			
		Errors should return:
		
			{ 
			"error":
				{ 
				"code":<VALUE>, 
				"message":<STRING> 
				} 
			}

AVAILABLE SERVICES:

	Service Root:
	
		All api's will be routed in the URI:
		
			/api/v1/
			
	Service Port:
	
		Unless there is a good reason to use something else, the API wil, use:
		
			TCP: 8080

	Services:
	
		/device/*	Get
We need one that is used for registration of events and uses a web-socket to then send push notifications.

We need:

	/search
	
		POST along with criteria

	/devices				Obtains a list of all available devices
	/devices/[location]		Obtains a list of devices in a location
	
		Only HEAD/GET are valid for this service
	
	/locations				Obtains a list of all available locations

		Only HEAD/GET are valid for this service

	/devices/<id>					Operations on a single device	(GET/DELETE/HEAD/PATCH/POST/PUT)
	/devices/<id>/[<ACTION>]		Actions on a single device		(PUT)
										watch/unwatch	- Flag to be watched (Get stats)
										fav/unfav		- Flag favourite (At top of list)
	/locations/<id>					Operations on a single location	(GET/DELETE/HEAD/PATCH/POST/PUT)
	/iface/<device>					All interfaces
	/iface/<device>/<id>			Interface operations
