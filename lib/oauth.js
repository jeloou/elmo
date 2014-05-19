var querystring = require('querystring')
  , https = require('https')
  , http = require('http')
  , sha1 = require('./sha1')
  , URL = require('url')
  , util = require('util')
  , _ = require('underscore')._;

var OAuth = function OAuth(options) {
  var that = this;
  
  if (!(this instanceof OAuth)) {
    return new(OAuth)(options);
  }
  
  this.token = !options.token? {}: {
    'key' : options.token.oauthToken,
    'secret' : options.token.oauthTokenSecret
  };
  
  this.consumer = {
    'key': options.appKey,
    'secret': options.appSecret
  };
  
  this.headers = options.headers || {};
};

_(OAuth.prototype).extend({
  'addHeaders' : function(headers) {
    _(this.headers).extend(headers);
    
    return this;
  }, 
  'request' : function(method, url /* [data], [callback]*/){
    var args = Array.prototype.slice.call(arguments, 2);
    
    var callback = args.pop() || function() {},
    data = args.shift();
    
    new(Request)(
      method, url, data, this.headers, this.consumer, this.token
    ).send(callback); 
    
    return this;
  }, 
  'requestToken' : function(url, callback){
    var that = this;
    
    this.addHeaders({ 'Content-Length': 0 })
      .request('post', url, function(res){
	res.setEncoding('utf8');
	res.on('data', function(data){
	  if ( res.statusCode !== 200 ){
	    callback(data, null);
	    return;
	  }
	  
	  token = querystring.parse(data);
	  that.token = {
	    'key' : token.oauth_token,
	    'secret' : token.oauth_token_secret
	  };
	  
	  callback(null, token);
	  return;
	});
      });
  },
  'accessToken' : function(url /* [verifier], [callback]*/){
    var args = Array.prototype.slice.call(arguments, 1),
    that = this;
    
    console.log(args);
    var callback = args.pop() || function(){},
    verifier = args.shift();
    
    url = URL.parse(url);
    var query = url.query || null;
    
    url = url.protocol+'//'+url.hostname+url.pathname;
    
    if ( query ){
      query = querystring.parse(query);
      _(query).extend({
	'oauth_verifier' : verifier
      });
    }else{
      query = {
	'oauth_verifier' : verifier
      };
    }
    
    url = [
      url, querystring.stringify(query)
    ].join('?');
    
    this.addHeaders({ 'Content-Length' : 0 })
      .request('post', url, function(res){
	res.setEncoding('utf8');
	
	res.on('data', function(data){
	  if ( res.statusCode !== 200 ){
	    callback(data, null);
	    return;
	  }
	  
	  token = querystring.parse(data);
	  that.token = {
	    'key': token.oauth_token,
	    'secret': token.oauth_token_secret
	  };
	  callback(null, token);
	  return;
	});
	
      });
  }
}); 


var Request;
Request = function(method, url, data, headers, consumer, token){
  var that = this;

  if (!(this instanceof Request)) {
    return new(Request)(method, url, data, headers, consumer, token);
  }
  
  this.method = method.toLowerCase();
  this.url    = url;
  this.data   = data || {};
  this.consumer = consumer;
  this.token = token || {};
  
  this.headers = {};
  if ( headers ){
    _.extend(
      this.headers, headers
    );
  }
};

Request.prototype.getNonce = function(length, base64){
  var nonce = [], timestamp, char;
  
  base64 = ( base64 !== undefined )?base64 : true;
  length = ( length )?length : 32;
  
  timestamp = (+new(Date)).toString();
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
  var query, sorted_query, base_string, that;
  
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
  
  sorted_query = [];
  that = this;
  
  keys.forEach(function(key){
    sorted_query.push([
      key, that.url.query[key]
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
  var base_url = querystring.escape(this.url.protocol+'//'+this.url.host+this.url.pathname);
  base_string = [
    this.method, base_url, query
  ].join('&');
  
  
  /*
    Getting a signing key.
  */
  var signing_key = [
    this.consumer.secret, ( this.token.secret )?this.token.secret: ''
  ].join('&');
  
  console.log('Base string = ');
  console.log(base_string);
  
  console.log('Signing key = ');
  console.log(signing_key);
  
  return sha1.HMACSHA1(signing_key, base_string);
};

Request.prototype.authHeader = function(oauth_query){
  var auth_header = 'OAuth ', params = [];
  
  for ( var key in oauth_query ){
    params.push(
      util.format('%s="%s"', key, querystring.escape(oauth_query[key]))
    );
  }
  
  auth_header += params.join(', ');
  return auth_header;
};

Request.prototype.send = function(callback){
  var options, request, oauth_query, oauth_header, oauth_token;
  
  this.url = URL.parse(this.url);
  /*
    querystring.parse(undefined) -> {};
  */ 
  this.url.query = querystring.parse(this.url.query);
  oauth_query = {
    'oauth_consumer_key' : this.consumer.key, 
    'oauth_signature_method' : 'HMAC-SHA1',
    'oauth_nonce' : this.getNonce(),
    'oauth_timestamp' : Math.round(+new(Date)/1000).toString(),
    'oauth_version' : '1.0'
  }; 
  
  /*
    This handles the 'oauth_callback' for the 'request token' step
  */
  oauth_header = _.clone( 
    !_.has(this.url.query, 'oauth_callback')?oauth_query : _.extend(
      oauth_query, {
	'oauth_callback' : querystring.escape(this.url.query.oauth_callback) 
      }
    )
  ); 
  
  /*
    And this handles the 'oauth_verifier' for the 'access token' step
  */
  oauth_header = _.clone(
    !_.has(this.url.query, 'oauth_verifier')?oauth_query : _.extend( 
      oauth_query, { 
	'oauth_verifier' : this.url.query.oauth_verifier
      }
    )
  );
  
  /*
    
   */
  
  if ( this.token.key ){
    oauth_token = {
      'oauth_token' : this.token.key
    };
    
    _.extend(oauth_header, oauth_token);
    _.extend(this.url.query, oauth_token);
  }
  
  /*
    Adding oauth parameters to the query
  */
  oauth_query = _.clone(
    _.extend(
      this.url.query, oauth_query
    )
  );
  
  /*
    Extending the query with the data, if exists
  */
  if ( this.method === 'get' ){
    _.extend(
      this.url.query, this.data
    );
    this.data = {};
  }
  
  /*
    Adding the oauth_signature to the query
  */
  var signature = {
    'oauth_signature' : this.createSignature()
  }; 
  
  _.extend(this.url.query, signature);
  _.extend(oauth_header, signature);
  
  var path = [
    this.url.path,
    querystring.stringify(this.url.query)
  ].join('?');
  
  /*
    Adding oauth headers
  */
  _.extend(this.headers, {
    'Authorization' : this.authHeader(oauth_header)
  });
  
  console.log(this.headers); 
  
  options = {
    'method' : this.method,
    'host' : this.url.hostname, 
    'path' : this.url.path, 
    'headers' : this.headers
  };
  
  request = ((this.url.protocol === 'https:')?https:http).request(options, callback);
  request.end();
};

exports.Request = Request;
exports.OAuth = OAuth;
