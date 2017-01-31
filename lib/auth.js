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
  }, function (username, password, done) {
    var User = mongoose.model('User');
    User.findOne({username: username}, function(err, user) {
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
          email: username + '@temp.com',
          password: password,
          firstName: username,
          lastName: username,
          username: username,
          displayName: username
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

          // Authenticate after the user was created
          User.authenticate(username, password, function(err, user) {
            if (err) {
              return done(null, false, {
                message: 'Some fields did not validate.'
              });
            }
            if (user) {
              return done(null, user);
            } else {
              return done(null, null, {
                message: 'Incorrect login credentials.'
              });
            }
          });
        });
      }
    });
  });
};

FreePBX.prototype.authenticate = function(req, cb) {
  passport.authenticate('freepbx-auth', cb)(req);
};

module.exports = FreePBX;
