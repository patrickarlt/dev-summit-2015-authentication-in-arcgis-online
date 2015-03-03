var Confidence = require('confidence');

var store = new Confidence.Store({
  clientId: 'FILL ME IN',
  clientSecret: 'FILL ME IN',
  redirectUrl: '/auth/arcgis',
  secretKey: 'foo', // used to encrypt the cookie
  secure: false, // enable in production for https
  sessionLength: -1, // -1 for longest session possible for user
  postSignIn: '/', // page to redirect user to after sign in
  postSignOut: '/' // page to redirect user to after sign out
});

module.exports = function(key) {
  return store.get(key);
};