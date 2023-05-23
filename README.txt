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
	python3 -m venv venv
	python3 -m pip install --upgrade pip
	
Install dependencies:
	(Requires internet access)

	cd /d D:\NetadminAPI
	WINDOWS:
    venv\scripts\activate
    LINX:
    . venv/bin/activate
	python3 -m pip install --upgrade pip
	python3 -m pip install --upgrade mysql-connector-python
	python3 -m pip install --upgrade flask
    !! python3 -m pip install --upgrade flask_restful
    python3 -m pip install --upgrade flask_jwt


    Depreciated
	!! python -m pip install --upgrade requests
	!! python -m pip install --upgrade websocket
	!! python -m pip install --upgrade websocket-client
	!! python -m pip install --upgrade flask-cors	
    !! python3 -m pip uninstall PyJWT

The first time you run this script you will be asked to save the server fingerprint; please say yes.

UPGRADE:
----------------------------------------
(Requires internet access)

	python -m pip install --upgrade pip

ADD OR UPDATE ADMINISTRATOR
Run the "reset_admin" script and provide administrator name and password

    LINUX:
    $ ./reset_admin.sh

    WINDOWS
    $ reset_admin

DESIGN IDEALS
All of these web services should run in different threads
However, the port needs to be the same, so the listener needs to deal with the router.

REST API

	Methods:
		GET		Obtain a single record
		DELETE	Delete an individual record
		HEAD	Returns the same as GET, Payload only contains "COUNT"
		OPTIONS	Not used (Apart from CORS where necessary)
		PATCH	Update an existing record
		POST	Create a record
		PUT		Replace an existing record

	Header:
		All requests expect an Authentication-Bearer token in the header
	
    Request:
        {
        "netadmin":"1",     # Always use 1.0 or packet will be invalid
        "data":<CONTENT>
        }

	Response:
		All responses must return a valid JSON payload if possible, even if it is a null object: {}
		Valid responses should contain:
	
			{
			"data":<CONTENT>
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
		
			/netadmin
			
	Service Port:
	
		Unless there is a good reason to use something else, the API wil, use:
		
			TCP: 8080

	Services:
	
		/device/*	Get
We need one that is used for registration of events and uses a web-socket to then send push notifications.

We need:


    /auth
        POST            Login to obtain a token

	/search                 
        POST            along with criteria

	/nodes
        GET				Obtains a list of nodes
	    HEAD            Obtains a count of nodes
        POST            Add new node

	/nodes/?location=<LOCATION>
        GET     		Obtains a list of nodes in a location
	    HEAD            Obtains a count of nodes in a location
	
    /nodes/<id>
        GET             Obtain a single node
        PATCH           UPDATE single node (provided fields only)
        PUT             REPLACE single node (Overwrite all fields)

	/locations
        GET				Obtains a list of locations
	    HEAD            Obtains a count of locations

	/devices/<id>					Operations on a single device	(GET/DELETE/HEAD/PATCH/POST/PUT)
	/devices/<id>/[<ACTION>]		Actions on a single device		(PUT)
										watch/unwatch	- Flag to be watched (Get stats)
										fav/unfav		- Flag favourite (At top of list)
	/locations/<id>					Operations on a single location	(GET/DELETE/HEAD/PATCH/POST/PUT)
	/iface/<device>					All interfaces
	/iface/<device>/<id>			Interface operations
