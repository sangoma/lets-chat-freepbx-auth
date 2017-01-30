var fs = require('fs'),
    _ = require('lodash'),
    passport = require('passport'),
    FreePBXStrategy = require('./strategy'),
    mongoose = require('mongoose');

function FreePBX(options) {
  this.options = options;
  this.key = 'freepbx-auth';
  this.setup = this.setup.bind(this);
  this.getFreePBXStrategy = this.getFreePBXStrategy.bind(this);
  this.authenticate = this.authenticate.bind(this)
}

FreePBX.key = 'freepbx-auth';

FreePBX.prototype.setup = function() {
  passport.use(this.getFreePBXStrategy());
};

FreePBX.prototype.getFreePBXStrategy = function() {
  return new FreePBXStrategy({
    usernameField: 'username',
    passwordField: 'password'
  }, function (username, done) {
    var User = mongoose.model('User');
    User.findOne({username: username}, function(err, user) {
      if (err) {
        return done(null, false, {
          message: 'Some fields did not validate'
        });
      }
      console.log(user, username);
      if (user) {
        return done(null, user);
      } else {
        return done(null, null, {
          message: 'Iconrrect login credentials.'
        });
      }
    });
  });
};

FreePBX.prototype.authenticate = function(req, cb) {
  passport.authenticate('freepbx-auth', cb)(req);
};

module.exports = FreePBX;
