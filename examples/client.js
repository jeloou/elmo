var elmo = require('../');

var client = elmo.OAuth({
  appKey: 'V4dnUFZLY4gk',
  appSecret: 'az02uZiyIby91slluxj2HiJBF1I5aq9f',
  urls: {
    requestToken: 'http://www.plurk.com/OAuth/request_token',
    accessToken: 'http://www.plurk.com/OAuth/access_token',
    authorize: 'http://www.plurk.com/OAuth/authorize'
  }
});

client.on('error', function(err) {
  console.log(this);
});

client.requestToken(function(err, data) {
  console.log('data: ', data);
  process.stdin.on('readable', function() {
    var verifier = process.stdin.read();
    
    if (verifier != null) {
      verifier = verifier.toString();
      
      console.log('verifier: ', verifier);
      client.accessToken(verifier.substr(0, verifier.length-1), function(err, token) {
	console.log(token);
      });
    }
  });
});




