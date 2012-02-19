(function(){
    var querystring = require('querystring'),
        sha1 = require('./sha1'),
        URL = require('url');
    
    var OAuth;
    OAuth = function(options){
	
    };

    var Request;
    Request = function(method, url, data, headers, consumer, token){
	this.method = method.toLowerCase();
	this.url    = url;
	this.data   = data || {};
	this.consumer = consumer;
	this.token = token || {};

	this.headers = {
	    
	};
	for ( var k in headers ) { this.headers[k] = headers[k] } 
    };
    
    Request.prototype.getNonce = function(length, base64){
	var nonce = [], timestamp, char;

	base64 = ( base64 !== undefined )?base64 : true;
	length = ( length )?length : 32;

	timestamp = (new(Date)).getTime().toString();
	nonce.push(timestamp);

	if ( timestamp.length < length ){
	    for (var i = 0; i <= (length-timestamp.length); i++){
		char = String.fromCharCode(Math.floor(Math.random() * 26)+97);
		
		if ( Math.floor(Math.random()*2) )
		    char = char.toUpperCase();

		nonce.push(char);
	    }
	}

	nonce = nonce.join('');
	return ( base64 )?Buffer(nonce).toString('base64') : nonce;
    };

    Request.prototype.createSignature = function(args){
	var method, baseURL, query;
	
	if ( !args.method ){
	    throw 'Missing method in request';
	    return;
	}
	method = args.method.toUpperCase();
	
	if ( !args.baseURL ){
	    throw 'Missing base URL in request';
	    return;
	}
	baseURL = querystring.escape(args.baseURL);

	/*
	  Parameter string
	 */
	
	query = args.query;
	var keys = [];
	for ( var key in query ){
	    if ( query.hasOwnProperty(key) ){
		keys.push(key);
	    }
	}
	keys.sort();
	
	sorted_query = [];
	keys.forEach(function(key){
	    sorted_query.push([
		key, query[key]
	    ]);
	});
	    
	query = [];
	sorted_query.forEach(function(field){
	    query.push([
		querystring.escape(field[0]),
		querystring.escape(field[1])
	    ].join('='));
	});
	query = query.join('&');
	query = query.replace(/\!/g, '%21');
	query = querystring.escape(query);

	console.log('Parameter string = '+query);
	/*
	  Creating the signature base string
	 */
	
	var base_string = [
	    method, baseURL, query
	].join('&');
	console.log('Base string = '+base_string); 
	
	/*
	  Getting a signing key. TODO
	 */
	var consumer_secret = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw', 
	    token_secret = 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
	
	var signing_key = [
	    consumer_secret, token_secret
	].join('&');
	console.log('Signing key = '+signing_key); 

	return sha1.HMACSHA1(signing_key, base_string);
    };

    Request.prototype.authHeader = function(oauth_query){
	var auth_header = 'OAuth ', params = [];
	
	for ( var key in oauth_query ){
	    params.append(
		util.format('%s="%s"', key, querystring.stringify(oauth_query[key]))
	    );
	}
	auth_header += params.join(', ');
    };
    
    Request.prototype.send = function(callback){
	var oauth_query, options, request;

	oauth_query = {
	    'oauth_consumer_key' : this.consumer.key, 
	    'oauth_signature_method' : 'HMAC-SHA1',
	    'oauth_callback' : '',
	    'oauth_nonce' : this.getNonce(),
	    'oauth_timestamp' : (new(Date)).getTime().toString(),
	    'oauth_version' : '1.0'
	}
	
	oauth_query = oauth_query.update({
	    'oauth_signature' : this.createSignature(oauth_query)
	});

	options = {
	    'auth' : this.oauthHeader(oauth_query),
	    'headers' : this.headers,
	    'method' : this.method
	};

	this.url = URL.parse(this.url);
	if ( this.method === 'get' ){
	    if ( !/&$/.test(this.url.path) ) 
		this.url.path += '&';

	    this.url.path += querystring.stringify(
		query.update(this.data)
	    );
	    this.data = {};
	}
	
	request = http.request(options, callback);
	request.end(this.data);
    };
    
    exports.Request = Request;
    
    //exports.OAuth = OAuth;
})();