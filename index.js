const deprecate = require('util');
const Authorization = require('./authorization');

module.exports = deprecate((app) => {
    app.loopback.modelBuilder.mixins.define('Authorization', Authorization);
}, 'DEPRECATED: Use mixinSources, see https://github.com/Emiya0306/loopback-ds-authorization-mixin');
