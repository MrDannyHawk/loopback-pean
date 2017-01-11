
var path = require('path');

var app = require(path.resolve(__dirname, './server/server'));
var ds = app.datasources.db;
ds.automigrate();