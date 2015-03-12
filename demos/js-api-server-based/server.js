var Hapi = require('hapi');
var Hoek = require('hoek');
var path = require('path');
var request = require('request');

var config = require('./config.js');
var server = new Hapi.Server();
server.connection({ port: 3000 });

// configure a folder of templates
server.views({
    engines: {
      html: require('handlebars')
    },
    path: path.join(__dirname, 'templates')
});

// Register our plugins:
// * bell for the OAuth 2.0 workflow
// * hapi-auth-cooke for persisting auth in cookies
// * good for logging
server.register([
  { register:require('bell') },
  { register:require('hapi-auth-cookie') },
  {
    register: require('good'),
    options: {
      reporters: [{
        reporter: require('good-console'),
        args:[{ log: '*', request: '*', server: '*', ops: '*' }]
      }]
    }
  }
], function (err) {
  if (err) {
    console.log(err);
    return;
  }
});

// Get a segment of out of our servers cache for storing user sessions
// my default this is an in-memory cache which means that all sessions
// will be cleared when your server is killed. Ideally this should be
// persisted my configurng the server.cache option http://hapijs.com/api#server-options
var sessions = server.cache({
  segment: "sessions",
  expiresIn: (14 * 24 * 60 * 60 * 1000) - (5 * 60 * 1000) // by default 2 weeks - 5 minutes
});

// Register a cookie called 'redirect' to store the value of the page to
// redirect a user to after sign in. This cookie should be secured because
// we dont want to redirect the user to a malicious page after signin this helps,
// confirm that the server set this cookie and not an attacker
server.state('redirect', {
  ttl: null,
  encoding: 'iron',
  isSecure: config('/secure'),
  password: config('/secretKey')
});

// Configure cookie authentcation defining where to direct users to after
// a failed authentication and how to validate a cookie be retriving it from
// the session cache.
server.auth.strategy('session', 'cookie', {
  password: config('/secretKey'),
  cookie: 'arcgis_online_session',
  redirectTo: '/sign-in',
  isSecure: config('/secure'),
  appendNext: true,
  validateFunc: function(session, callback) {
    sessions.get(session.sid, function(err, cached) {

      if (err) {
        return callback(err, false);
      }

      if (!cached) {
        return callback(null, false);
      }

      return callback(null, true, cached.account);
    });
  }
});

// Configure bell to provide the OAuth 2.0 workflow by defining
// a custom provider with the ArcGIS Online OAuth 2.0 endpoint and
// a function to get an normalize the users profile.
server.auth.strategy('arcgis', 'bell', {
  provider: {
    protocol: 'oauth2',
    auth: 'https://www.arcgis.com/sharing/rest/oauth2/authorize',
    token: 'https://www.arcgis.com/sharing/rest/oauth2/token',
    profile: function(credentials, params, get, callback){
      get('https://www.arcgis.com/sharing/rest/portals/self', {
        token: credentials.token,
        f: 'json'
      }, function(response){
        credentials.expiresIn = params.expires_in; // pull out the expires_in param so we can save it later
        credentials.profile = {
          username: response.user.username,
          firstName: response.user.firstName,
          lastName: response.user.lastName,
          fullName: response.user.fullName,
          email: response.user.email,
          orgId: response.orgId,
          urlKey: response.urlKey,
          ssl: response.allSSL
        };

        callback();
      });
    }
  },
  providerParams: {
    expiration: -1 // get longest possible refresh token
  },
  password: config('/secretKey'),
  clientId: config('/clientId'),
  clientSecret: config('/clientSecret'),
  isSecure: config('/secure')
});

// The route that will authenticate with ArcGIS Online. The `handler` is run when authentication is complete.
// Because `try` is specified in the auth config auth is not technically required. If auth is successful we
// will store the users session in our session cache and look it up by storing their username in a secure cookie.
// The cookie will expire shortly before the users refresh token does
server.route({
  method: ['GET', 'POST'],
  path: config('/redirectUrl'),
  config: {
    auth: {
      strategy: 'arcgis',
      mode: 'try'
    },
    handler: function(request, reply) {
      // handle an error in the auth process. This could redirect the user to another page
      if (!request.auth.isAuthenticated) {
        var status = JSON.stringify({
          error: request.auth.error.message
        }, null, 2);

        return reply('<pre>' + Hoek.escapeHtml(status) + '</pre>');
      }

      var account = request.auth.credentials; // all credential and profile info
      var sid = account.profile.username; // username will be stored in the cookie and be used to lookup the session in cache
      var ttl = (account.expiresIn - (30*60)) * 1000; // cookie is valid for the duration of the refresh token minus a half hour

      // set the session in our cache with sid (username) as the key
      sessions.set(sid, {
        account: account
      }, ttl, function(error) {
        if (error) {
          reply(error);
        }

        // set the cookie, request.auth.session is the session auth strategy we setup above
        request.auth.session.set({
          sid: sid
        });

        // validate that the redirect URL is going somewhere on our site not a malicious page
        var redirectTo = (request.state.redirect && request.state.redirect[0] === '/') ? request.state.redirect : config('/postSignIn');

        return reply.redirect(redirectTo);
      });
    }
  }
});

// Our applicaitons sign in route, we have a sign-in route and an auth route because this gives us a chance to
// set the redirect cookie for after the user signs in. If the session auth fails on another route it will append
// the url to redirect to with ?next=page. We set this in the cookie and redirect the user there after sign in
server.route({
  method: ['GET'],
  path: '/sign-in',
  config: {
    auth: {
      strategy: 'session',
      mode: 'try'
    },
    plugins: { 'hapi-auth-cookie': { redirectTo: false } },
  },
  handler: function(request, reply) {
    if(request.auth.isAuthenticated){
      return reply.redirect(config('/postSignIn'));
    }

    return reply.redirect('/auth/arcgis').state('redirect', request.query.next || config('/postSignIn'));
  }
});

// to sign a user out we simply need to clear their auth cookie
server.route({
  method: ['GET'],
  path: '/sign-out',
  handler: function (request, reply) {
    request.auth.session.clear();
    return reply.redirect(config('/postSignOut'));
  }
});

// homepage route, we will try to authenticate the user with a session (mode=try) but if they dont have
// a session we will set redirectTo=false in our 'hapi-auth-cookie' plugin so they wont be redirected.
// This means that users can be signed in or out when visiting this page
server.route({
  path: '/',
  method: 'GET',
  config: {
    auth: {
      strategy: 'session',
      mode: 'try'
    },
    plugins: { 'hapi-auth-cookie': { redirectTo: false } },
  },
  handler: function(request, reply) {
    var status = JSON.stringify({
      isLoggedIn: request.auth.isAuthenticated,
      credentials: (request.auth.isAuthenticated) ? request.auth.credentials: null
    }, null, 2);

    reply('<a href="/sign-in">Sign In</a><br><pre>' + Hoek.escapeHtml(status) + '</pre>');
  }
});

// helper function to generate a token
function generateToken(incomingRequest, reply){
  if(incomingRequest.auth.isAuthenticated){
    request({
      method: 'POST',
      url: 'https://www.arcgis.com/sharing/rest/oauth2/token/',
      form: {
        client_id: config('/clientId'),
        grant_type: 'refresh_token',
        refresh_token: incomingRequest.auth.credentials.refreshToken
      },
      json: true
    }, function(error, response, body){
      if(error){
        reply({
          error: 'could not generate token',
          details: error
        });
      } else {
        reply({
          expires: new Date().getTime() - (body.expires_in * 1000) - (2 * 60 * 1000),
          server: "https://www.arcgis.com",
          ssl: incomingRequest.auth.credentials.profile.ssl,
          token: body.access_token,
          userId: body.username
        });
      }
    });
  } else {
    reply.redirect('/sign-in').state('redirect', request.path);
  }
}

// This is our application page, a valid session is required to access it
server.route({
  method: ['GET'],
  path: '/app',
  config: {
    auth: 'session', // require a valid session to access the page
    pre: [ {method: generateToken, assign: 'token'} ], // generate a token and assign it to `request.pre.token` using the generateToken helper
  },
  handler: function(request, reply){
    // render the view inserting the server side token
    reply.view('app', {
      token: JSON.stringify(request.pre.token)
    });
  }
});

// Will generate a new token for a user whose token is about to run out
server.route({
  method: ['GET'],
  path: '/refresh',
  config: {
    pre: [ {method: generateToken, assign: 'token'} ], // generate a token and assign it to `request.pre.token` using the generateToken helper
    plugins: { 'hapi-auth-cookie': { redirectTo: false } }, // don't redirect if auth fails
    auth: { strategy: 'session', mode: 'try' } // try to authenticate via `session` but don't give a hard failure
  },
  handler: function(request, reply){
    // if we are authenticated respond with a token otherwise respond with an error
    if(request.auth.isAuthenticated){
      reply(request.pre.token);
    } else {
      reply({error: 'error'});
    }
  }
});

server.start(function(){
  server.log('server', 'started on port 3000');
});