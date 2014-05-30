var elmo = require('../');

var client = elmo.OAuth({
  appKey: '<your app key>',
  appSecret: '<your app secret>',
  urls: {
    requestToken: 'http://www.plurk.com/OAuth/request_token',
    accessToken: 'http://www.plurk.com/OAuth/access_token',
    authorize: 'http://www.plurk.com/OAuth/authorize'
  }
});

client.on('error', function(err) {
  console.log(err);
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
