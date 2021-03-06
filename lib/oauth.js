var querystring = require('querystring')
  , Emitter = require('events').EventEmitter
  , https = require('https')
  , http = require('http')
  , sha1 = require('./sha1')
  , URL = require('url')
  , util = require('util');

function extend(obj) {
  var args = Array.prototype.slice.call(arguments, 1);

  args.forEach(function(source) {
    for(var prop in source) {
      obj[prop] = source[prop];
    }
  });
  
  return obj;
}

function extendQuery(url, obj) {
  var query; 

  url = URL.parse(url);
  query = url.query;
  
  query = (query)? extend(querystring.parse(query), obj) : obj;
  url = [
    url.protocol, '//', url.hostname, url.pathname
  ].join('');
  
  return [
    url, querystring.stringify(query)
  ].join('?');
}

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
  
  this.urls = {
    requestToken: null,
    accessToken: null,
    authorize: null
  };
  
  if (options.urls) {
    for (var k in this.urls) {
      if (options.urls.hasOwnProperty(k)) {
	this.urls[k] = options.urls[k];
      }
    }
  }
  
  this.headers = options.headers || {};
  
  Emitter.call(this);
};
util.inherits(OAuth, Emitter);

OAuth.prototype.addHeaders = function(headers) {
  extend(this.headers, headers);
  return this;
};

OAuth.prototype.request = function(method, url /* [data], [callback]*/) {
  var args = Array.prototype.slice.call(arguments, 2)
    , request;
  
  var callback = args.pop() || function() {}
    , data = args.shift();
  
  request = new(Request)(
    method, url, data, this.headers, this.consumer, this.token
  );
  request.on('error', this.emit.bind(this, 'error'));
  request.send(callback);
  
  return this;
};

OAuth.prototype.requestToken = function(/* [url], [callback]*/) {
  var args = Array.prototype.slice.call(arguments)
    , that = this;

  var callback = args.pop() || function() {}
    , url = args.shift();
  
  if (this.urls.requestToken && !url) {
    url = this.urls.requestToken;
  }
  
  this
    .addHeaders({'Content-Length': 0})
    .request('post', url, function(res) {
      res.setEncoding('utf8');
      res.on('data', function(data) {
	if (res.statusCode !== 200) {
	  callback(null, data);
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
};
OAuth.prototype.authorize = function(/* [url]*/) {
  var args = Array.prototype.slice.call(arguments);
  
  var url = args.shift();
  if (this.urls.authorize && !url) {
    url = this.urls.authorize;
  }

  return extendQuery(url, {
    'oauth_token': this.token.key
  });
};

OAuth.prototype.accessToken = function(/* [url], [verifier], [callback]*/) {
  var args = Array.prototype.slice.call(arguments)
    , that = this;

  var callback = args.pop() || function() {} 
    , verifier = args.pop()
    , url = args.shift();

  if (this.urls.accessToken && !url) {
    url = this.urls.accessToken;
  }
  
  url = extendQuery(url, {
    'oauth_verifier': verifier
  });

  this
    .addHeaders({ 'Content-Length' : 0 })
    .request('post', url, function(res) {
      res.setEncoding('utf8');
      
      res.on('data', function(data) {
	if (res.statusCode !== 200) {
	  callback(null, data);
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
};

var Request = function Request(method, url, data, headers, consumer, token) {
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
  if (headers) {
    extend(this.headers, headers);
  }

  Emitter.call(this);
};
util.inherits(Request, Emitter);

Request.prototype.getNonce = function(length, base64) {
  var nonce = [], timestamp, char;
  
  base64 = (base64 !== undefined)? base64 : true;
  length = length? length : 32;
  
  timestamp = (+new(Date)).toString();
  nonce.push(timestamp);
  
  if (timestamp.length < length) {
    for (var i = 0; i <= (length-timestamp.length); i++) {
      char = String.fromCharCode(Math.floor(Math.random() * 26)+97);
      
      if (Math.floor(Math.random()*2))
	char = char.toUpperCase();
      
      nonce.push(char);
    }
  }
  
  nonce = nonce.join('');
  return ( base64 )?Buffer(nonce).toString('base64') : nonce;
};

Request.prototype.createSignature = function(oauth_query) {
  var query, sorted_query, base_string, that;
  
  this.method = this.method.toUpperCase();
  /*
    Parameter string
  */
  var keys = [];
  for (var key in this.url.query) {
    if (this.url.query.hasOwnProperty(key)) {
      keys.push(key);
    }
  }
  keys.sort();
  
  sorted_query = [];
  that = this;
  
  keys.forEach(function(key) {
    sorted_query.push([
      key, that.url.query[key]
    ]); 
  }); 
  
  query = [];    
  sorted_query.forEach(function(field) {
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
  
  return sha1.HMACSHA1(signing_key, base_string);
};

Request.prototype.authHeader = function(oauth_query) {
  var auth_header = 'OAuth ', params = [];
  
  for (var key in oauth_query) {
    params.push(
      util.format('%s="%s"', key, querystring.escape(oauth_query[key]))
    );
  }
  
  auth_header += params.join(', ');
  return auth_header;
};

Request.prototype.send = function(callback) {
  var options, request, oauth_query, oauth_header, oauth_token;
  
  this.url = URL.parse(this.url);
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
  oauth_header = extend(
    {}, !this.url.query.hasOwnProperty('oauth_callback')? oauth_query : extend(
      oauth_query, {
	'oauth_callback' : querystring.escape(this.url.query.oauth_callback) 
      }
    )
  ); 
  
  /*
    And this handles the 'oauth_verifier' for the 'access token' step
  */
  oauth_header = extend(
    {}, !this.url.query.hasOwnProperty('oauth_verifier')? oauth_query : extend( 
      oauth_query, {
	'oauth_verifier' : this.url.query.oauth_verifier
      }
    )
  );
  
  /*
    
   */
  
  if (this.token.key) {
    oauth_token = {
      'oauth_token' : this.token.key
    };
    
    extend(oauth_header, oauth_token);
    extend(this.url.query, oauth_token);
  }
  
  /*
    Adding oauth parameters to the query
  */
  oauth_query = extend(
    {}, extend(this.url.query, oauth_query));
  /*
    Extending the query with the data, if exists
  */
  if (this.method === 'get') {
    extend(this.url.query, this.data);
    this.data = {};
  }
  
  /*
    Adding the oauth_signature to the query
  */
  var signature = {
    'oauth_signature' : this.createSignature()
  }; 
  
  extend(this.url.query, signature);
  extend(oauth_header, signature);
  
  var path = [
    this.url.path,
    querystring.stringify(this.url.query)
  ].join('?');
  
  /*
    Adding oauth headers
  */
  extend(this.headers, {
    'Authorization': this.authHeader(oauth_header)
  });
  
  options = {
    'method' : this.method,
    'host' : this.url.hostname, 
    'path' : this.url.path, 
    'headers' : this.headers
  };
  
  request = ((this.url.protocol === 'https:')? https : http).request(options, callback);
  request.on('error', this.emit.bind(this, 'error'));
  request.end();
};

exports.Request = Request;
exports.OAuth = OAuth;
