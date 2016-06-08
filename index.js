var shapeful = require('shapeful');
var fs = require('fs');
var jwt = require('jsonwebtoken');
var path = require('path');
var Promise = require('es6-promises');
var promisify = require('./libs/util').promisify;
var request = require('coviu-sdk-http').request;
var cuid = require('cuid');
var Events = require('events');

/**
 * OAuth2Client wraps up an api invocation in the required OAuth2 Authorization behaviour.
 * apiKey: The issued api client key
 * keySecret: The issued secret with the api key
 * service: the `coviu-sdk-http` request structure for the service.
 */
exports.OAuth2Client = function(apiKey, keySecret, service) {
  var clientGrant = null;
  var tokenRequest;
  var oauth2 = {
    /*
      Recover an access token and refresh token by following the OAuth2 password grant flow.
    */
    getAccessToken: function(email, password) {
      var opts = {user: email, pass: password};
      return passwordFlow(tokenRequest, opts);
    },

    /*
      Recover an access token and refersh token by following the OAuth2 client_credentials grant flow.
    */
    getClientAccessToken: function(){
      return clientCredentialsFlow(tokenRequest);
    },

    /*
      Refresh an access token.
    */
    refreshAccessToken: function(token) {
      var opts = {refreshToken: token};
      return refreshToken(tokenRequest, opts);
    },
    /*
     Decode the provided access token.
    */
    decodeAccessToken: function(at){
      return decodeAccessToken(at);
    },

    /*
      Attach automatic token refresh behaviour when recovering auth headers using the supplied grant.
    */
    userContext: function(grant) {
      return userContext(oauth2, grant);
    },

    /*
      Get the supplied client credentials.
    */
    getClientCredentials: function() {
      return {user: apiKey, pass: keySecret};
    },

    prepairGrant: function(t){
      t.next_refresh = Date.now() + (t.expires_in / 2 )*1000;
      t.gid = cuid();
      return oauth2.decodeAccessToken(t.access_token).then(function(res){
        t.userId = res.userId;
        return t;
      });
    },
    liftClientGrant: function(fn) {
      if (clientGrant === null) clientGrant = oauth2.getClientAccessToken().then(oauth2.userContext);
      return clientGrant.then(function(ctx){return ctx.lift(fn)});
    },
    getClientAuth: function() {
      if (clientGrant === null) clientGrant = oauth2.getClientAccessToken().then(oauth2.userContext);
      return clientGrant.then(function(ctx){return ctx.auth();});
    }
  };
  tokenRequest = service.path('/auth/token')
  .auth({user: apiKey, pass: keySecret})
  .post()
  .map(oauth2.prepairGrant);
  return oauth2;
};

function buildAuth(token) {
  return {
    'bearer': token
  };
}

function userContext(oauth2, grant) {
  var ctx;
  var refreshing;
  var auth = function() {
    return new Promise(function(resolve, reject) {
      if (ctx.grant.next_refresh > Date.now()) {
          return resolve(buildAuth(ctx.grant.access_token));
      } else {
        if (typeof refreshing === 'undefined') {
          refreshing = oauth2.refreshAccessToken(ctx.grant.refresh_token).then(function(g) {
            ctx.grant = g;
            refreshing = undefined;
            ctx.events.emit("refresh");
            return buildAuth(g.access_token);
          });
        }
        refreshing.then(resolve).catch(reject);
      }
    });
  };
  ctx = {
    auth: auth,
    userId: grant.userId,
    grant: grant,
    events: new Events.EventEmitter()
  };

  return ctx;
};

function passwordFlow(tokenRequest, opts) {
  return tokenRequest
  .form({grant_type: 'password', username: opts.user,password: opts.pass})
  .run()
};

function refreshToken(tokenRequest, opts) {
  return tokenRequest
  .form({grant_type: 'refresh_token',refresh_token: opts.refreshToken})
  .run()
};

function clientCredentialsFlow(tokenRequest) {
  return tokenRequest
  .form({grant_type: 'client_credentials'})
  .run()
};

function decodeAccessToken(t) {
  return new Promise(function(accept, reject){
    try {
      accept(jwt.decode(t));
    } catch (e) {
      reject(e);
    }
  });
};
