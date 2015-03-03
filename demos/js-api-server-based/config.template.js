var Confidence = require('confidence');

var store = new Confidence.Store({
  clientId: 'PUT YOUR CLIENT ID HERE',
  clientSecret: 'PUT YOUR CLIENT SECRET HERE',
  redirectUrl: 'PUT A REDIRECT URI HERE',
  secretKey: 'PUT ANY RANDOM STRING HERE TO ENCRYPT COOKIES',
  secure: false, // enable to use https for cookies and oauth workflow
  sessionLength: -1, // get the longest session possible for user
  postSignIn: '/', // page to redirect user to after sign in
  postSignOut: '/' // page to redirect user to after sign out
});

module.exports = function(key) {
  return store.get(key);
};