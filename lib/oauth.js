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

    Request.prototype.createSignature = function(oauth_query){
	var query, sorted_query, base_url, base_string;

	this.method = this.method.toUpperCase();
	/*
	  Parameter string
	 */
	
	var keys = [];
	for ( var key in this.url.query ){
	    if ( this.url.query.hasOwnProperty(key) ){
		keys.push(key);
	    }
	}
	keys.sort();

	keys.forEach(function(key){
	    sorted_query.push([
		key, this.url.query[key]
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

	/*
	  Creating the signature base string
	*/
	base_url = this.url.protocol+'://'+this.url.host+this.path;
	base_url = querystring.escape(base_url);

	base_string = [
	    this.method, base_url, query
	].join('&');
	
	/*
	  Getting a signing key.
	 */
	var signing_key = [
	    this.consumer.secret, ( this.token.secret )?this.token.secret: ''
	].join('&');

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
	var options, request;

	this.url = URL.parse(this.url);
	if ( !this.url.query ) this.url.query = {};

	this.url.query = this.url.query.update({
	    'oauth_consumer_key' : this.consumer.key, 
	    'oauth_signature_method' : 'HMAC-SHA1',
	    'oauth_callback' : '',
	    'oauth_nonce' : this.getNonce(),
	    'oauth_timestamp' : (new(Date)).getTime().toString(),
	    'oauth_version' : '1.0'
	});

	if ( this.method === 'get' ){
	    this.url.query = this.url.query.update(
		this.data
	    )
	    this.data = {};
	}
	
	this.url.query = this.url.query.update({
	    'oauth_signature' : this.createSignature()
	});

	options = {
	    'auth' : this.oauthHeader(oauth_query),
	    'headers' : this.headers,
	    'method' : this.method
	};
	request = http.request(options, callback);
	request.end(this.data);
    };
    
    exports.Request = Request;
    //exports.OAuth = OAuth;
})();