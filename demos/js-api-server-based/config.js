var Confidence = require('confidence');

var store = new Confidence.Store({
  clientId: 'y3w5YlMgyA90iTpK',
  clientSecret: '662371a58acf4110b7784c9a4dce9f07',
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