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
  }, function (userData, done) {
    var User = mongoose.model('User');
    User.findOne({username: userData.username}, function(err, user) {
      if (err) {
        return done(null, false, {
          message: 'Some fields did not validate'
        });
      }
      if (user) {
        return done(null, user);
      } else {
        // TODO: We need to create the user in mongo at this point
        var data = {
          email: userData.email || userData.username + '@temp.com',
          password: userData.password,
          firstName: userData.firstName || userData.username,
          lastName: userData.lastName || userData.username,
          username: userData.username,
          displayName: userData.displayName || userData.username,
          freepbxId: userData.freepbxId
        };

        console.log('Creating user:', data);
        var newUser = new User({ provider: 'local' })
        Object.keys(data).forEach(function(key) {
          newUser.set(key, data[key]);
        });

        // Save the new user
        newUser.save(function(err, savedUser){
          if(err || !savedUser){
            console.log("ERROR SAVING NEW USER: ", err)
            return done(null, null, {
              message: 'Could not create user in local mongo db.'
            });
          }
	  return done(null, savedUser);
        });
      }
    });
  });
};

FreePBX.prototype.authenticate = function(req, cb) {
  passport.authenticate('freepbx-auth', cb)(req);
};

module.exports = FreePBX;
