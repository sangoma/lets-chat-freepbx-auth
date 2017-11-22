/**
* Module dependencies.
*/
var passport = require('passport'),
  exec = require('child_process').exec,
  util = require('util'),
  child;
var lookup = function(obj, field) {
  if (!obj) { return null; }
  var chain = field.split(']').join('').split('[');
  for (var i = 0, len = chain.length; i < len; i++) {
    var prop = obj[chain[i]];
    if (typeof(prop) === 'undefined') { return null; }
    if (typeof(prop) !== 'object') { return prop; }
    obj = prop;
  }
  return null;
};
/**
* `Strategy` constructor.
*
* The freepbx authentication strategy authenticates requests against a custom
* command that was used previously for xmpp_auth.
*
* Applications must supply a `verify` callback which calls the `done` callback 
* supplying a `user`, which should be set to `false` if the credentials are
* not valid.
* If an exception occured, `err` should be set.
*
* Optionally, `options` can be used to change the fields in which the
* credentials are found.
*
*/
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('freepbx authentication strategy requires a verify function');
  this._usernameField = options.usernameField || 'username';
  this._passwordField = options.passwordField || 'password';

  passport.Strategy.call(this);
  this.name = 'freepbx-auth';
  this.verify = verify;
}

/**
* Inherit from `passport.Strategy`.
*/
util.inherits(Strategy, passport.Strategy);

/**
* Authenticate request.
*
* @param {Object} req
* @api protected
*/
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  var userData = {
    username: lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField),
    password: lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField),
  }

  if (!userData.username || !userData.password) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }
  var self = this;
  var authParams = {};
  authParams['username'] = userData.username;
  authParams['password'] = userData.password;
  var encodedParams = new Buffer(JSON.stringify(authParams)).toString("base64");
  var command = "/var/lib/asterisk/bin/xmpp_auth.php jsonauth:"+encodedParams;
  child = exec(command,
    function (error, stdout, stderr) {
      if (error !== null) {
        console.log('exec error: ' + error);
      }
      if (!stdout || stderr || error) {
        return self.fail("Invalid");
      }
      var objData = JSON.parse(stdout);
      if ("status" in objData && !objData["status"]) {
        return self.fail("Invalid!");
      }
      console.log('User: '+userData.username+'Authenticated against freepbx!');
      userData["firstName"] = objData["data"]["fname"];
      userData["lastName"] = objData["data"]["lname"];
      userData["displayName"] = objData["data"]["displayname"];
      userData["email"] = objData["data"]["email"];
      userData["freepbxId"] = objData["data"]["id"];

      if (objData["data"]["uuid"]) {
        userData["uuid"] = objData["data"]["uuid"];
      }

      self.verify(userData, function(err, user) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(); }
        return self.success(user, {});
      });
    }
  );
}


/**
* Expose `Strategy`.
*/
module.exports = Strategy;
