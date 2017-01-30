var fs = require('fs'),
    _ = require('lodash'),
    passport = require('passport'),
    FreePBXStrategy = require('./strategy'),
    mongoose = require('mongoose');

function FreePBX(options, core) {
    this.options = options;
    this.core = core;
    this.key = 'freepbx';
    this.setup = this.setup.bind(this);
}

FreePBX.prototype.setup = function() {
    getAuthenticationStatus();
};

module.exports = FreePBX;
