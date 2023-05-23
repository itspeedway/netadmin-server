# netadmin-api
An API definition allowing third parties to expose their data to the Netadmin Client

STATE:  EXPERIMENTAL - USE AT YOUR OWN RISK

# Introduction

Please see netadmin-server for an example server using this API

## How it works

A Netadmin client (netadmin-webclient for example) will connect to an API asking what features
it supports and the server must return its capabilities. From here, the client will request authentication
followed by requests to your API.

A Netadmin API server can run on any port you like, but the default is 4010. The full URL is required when connecting your client
to a server (For example: https://example.com:4010)

The Netadmin webclient, by default will expect the netadmin api to be published in route "/netadmin" (https://example.com:4010/netadmin)

# API Reference

## Capabilities API

STATUS:         PRE-RELEASE BETA

Capabilites can return different datasets based on authentication if the
designer requires this.

The capabilities API can over-ride the base URLS's used by the API and/or add additional
servers that the clent shoud connect to.

When servers are defined, the system will contact the capabilities API of each and add them
as connected servers.

URL:            /netadmin
CONTENT-TYPE:   application/json'
AUTHENTICATION: Public and Private
REQUEST:        GET
    {}
RESPONSE:
    Success:    HTTP/200
    {
        "servers":[ "192.168.1.1", "192.168.1.5" ],
        "capabilities":{
            "auth":{
                "url":string = "/netadmin/auth"
            },
            "nodes":{
                "url":string = "/netadmin/nodes"
            },
            "places":{
                "url":string = "/netadmin/places"
            },
            "message-queue":{
                "type":string = mqnull | mqpython | mqtt
                "port":int
            }
        },
    }

    Failure:    HTTP/404
    {
        "code":int              # Error code
        "message":string        # Error Message
    }


## Authentication API

URL:            As defined in capabilities
CONTENT-TYPE:   application/json'
AUTHENTICATION: None
REQUEST:        POST
    {
        "username":string,      # REQUIRED - EMAIL ADDRESS
        "password":string       # REQUIRED - PASSWORD
    }
RESPONSE:
    Success:    HTTP/200
    {
        "token":string          # Token
    }

    Failure:    HTTP/203
    {
        "code":int              # Error code
        "message":string        # Error Message
    }


# EXPERIMENTAL / NOT IMPLEMENTED BEYOND THIS POINT


## Message Object

A Message object has the following members:

jsonrpc - STRING - The version of the JSON-RPC protocol. MUST be exactly "2.0".

```
Interface Message { 

	// JSON-RPC Header.
    jsonrpc:string = "2.0";

```

## Request Object
See JSON-RPC Specification for further details:

A Request object extends the Message object with the following members:

method - STRING - Name of the method to be invoked.
params - OBJECT - (Optional) Parameter values for the method
id - INTEGER - (Optional) Identifier established by the client, when omitted it is treated as a notification.

```
Interface Request Extends Message { 

	// The request id.
	id: integer;

	// Method to be invoked
	method: string;

	// Optional Parameters
	params: array | object;
}
```

## Response Object
See JSON-RPC Specification for further details:

A Response object extends the Message object with the following members:

result - OBJECT - Required upon success, must not exit if an error is included.
error - OBJECT - Required upon error, must not exist if successful
id - INTEGER - This is used to match to the request.id

```
Interface Response Extends Message { 

	// The request id allowing the response to be tied to a request.
	id: integer;

	// Error when not successful
	error: ErrorResponse;

	// Result when request is successful
	result: array | boolean | null | number | object | string ;
}
```

## Notification

A Notification is a request object without an id member. A server must never respond to a notification.

```
Interface Notification Extends Message {
	// Method to be invoked
	method: string;

	// Optional Parameters
	params: array | object;
}
```

## ErrorResponse

An Error response will contain the following members in the "error" object:

code - INTEGER - The error type that occurred.
message - STRING - A short description of the error.
data - OBJECT/PRIMITIVE (Optional) additional information

```
Interface ErrorResponse {

	// The error type that occurred.
	code: integer;

	// A short description of the error.
	message: string;

	// Optional additional information
	data: array | boolean | null | number | object | string ;
}
```

JSON-RPC reserves the following error messages:

code 	message 	meaning
-32700 	Parse error 	Invalid JSON was received by the server.
An error occurred on the server while parsing the JSON text.
-32600 	Invalid Request 	The JSON sent is not a valid Request object.
-32601 	Method not found 	The method does not exist / is not available.
-32602 	Invalid params 	Invalid method parameter(s).
-32603 	Internal error 	Internal JSON-RPC error.
-32000 to -32099 	Server error 	Reserved for implementation-defined server-errors.

## Batch processing

This is defined in JSON-RPC specification but is not used in the Netadmin API.

## Capabilities Request

A request from the client to a server to find out what capabilities are supported
The request is allowed to return different results before and after authentication

*Request*
METHOD: capabilities
PARAMS: CapabilitiesRequest or undefined

NOTE: CapabilitiesRequest is Experimental at this time

*Response*
RESULT: ServerCapabilities
ERROR: An ErrorResponse object if an error has occurred


## CapabilitiesRequest

EXPERIMENTAL AND UNSUPPORTED

A Request from the client for capabilities of a server

```
Interface CapabilitiesRequest {
    client-capabilities: ClientCapabilities;
}
```

## ServerCapabilities

A response from a server providing capabilities.

```
Interface ServerCapabilities {
    // Authentication information
    authentication: Authentication
}
```

```
Interface Authentcation {
    // Path that should be used for authentication
    path: string = "/netadmin/auth"
}
```

### ClientCapabilities

EXPERIMENTAL AND UNSUPPORTED

Defines what capabilities are supported by the client. This allows the server to offer the services

```
Interface ClientCapabilities {
    live-log: boolean = false
}
```







