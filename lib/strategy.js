/**
* Module dependencies.
*/
var passport = require('passport'),
    exec = require('child_process').exec,
    util = require('util'),
    child;


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

    passport.Strategy.call(this);
    this.name = 'freepbx';
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
Strategy.prototype.authenticate = function(req) {

    var self = this;
    this.verify(function(err, user, password) {
        if (err) { return self.error(err); }
        if (!user || !password) { return self.fail(); }
        var command = "/var/lib/asterisk/bin/xmpp_auth.php auth:"+user+":localhost:"+password; 
        child = exec(command,
           function (error, stdout, stderr) {
              // console.log('stdout: ' + stdout);
              // console.log('stderr: ' + stderr);
              if (error !== null) {
                  console.log('exec error: ' + error);
              }
              if (stderr) {
                  return false;
              }
              return true;
        });
        if (child) {
          self.success(user, {});
        }
        else {
          self.fail("User or password invalid");
        }
    });
}


/**
* Expose `Strategy`.
*/ 
module.exports = Strategy;
