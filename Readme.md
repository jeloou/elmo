# elmo


elmo is a simple OAuth client for Node.js, useful for writing programs that 
interact with services using the version 1.0a of the OAuth protocol. Here is a [list](http://en.wikipedia.org/wiki/OAuth#List_of_OAuth_service_providers) with some of the service providers.

### Getting started 

Install with [npm](http://npmjs.org/)

```
npm install elmo
```

### Using the library

The library is pretty simple to use, here is an example using the [Plurk](http://www.plurk.com) API.

```js
var elmo = require('elmo');

var client = elmo.OAuth({
  appKey: '<your app key>',
  appSecret: '<your app secret>',
  urls: {
    requestToken: 'http://www.plurk.com/OAuth/request_token',
    accessToken: 'http://www.plurk.com/OAuth/access_token',
    authorize: 'http://www.plurk.com/OAuth/authorize'
  }
});

client.requestToken(function(err, data) {
  console.log('Now go to', client.authorize());
  console.log('and introduce the code:');
  
  process.stdin.on('readable', function() {
    var verifier = process.stdin.read();
    
    if (verifier != null) {
      verifier = verifier.toString();
      client.accessToken(verifier.substr(0, verifier.length-1), function(err, token) {
	/* Now you have an access token */
	console.log(token);
	
	/* and the client can make requests */
	client.request('get', 'http://www.plurk.com/APP/Profile/getOwnProfile', function(res) {
	  res.setEncoding('utf8');
	  res.on('data', function(data) {
	    console.log('me: ', data);
	  });
	});
      });
    }
  });
});
```
### Important note

I don't recommend using this in production. Some popular libraries have a 
great support for the OAuth protocol, like [request](https://github.com/mikeal/request). But if you're bored and want to play with new libraries, go ahead. 

### Contributing 

Feel free to open a pull request with a nice feature or a fix for some bug. 

### License

See the `LICENSE.md` file.
