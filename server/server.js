// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-example-passport
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT
'use strict';

var loopback = require('loopback');
var boot = require('loopback-boot');
var app = module.exports = loopback();
var cookieParser = require('cookie-parser');
var session = require('express-session');

// Passport configurators..
var loopbackPassport = require('loopback-component-passport');
var PassportConfigurator = loopbackPassport.PassportConfigurator;
var passportConfigurator = new PassportConfigurator(app);

/*
 * body-parser is a piece of express middleware that
 *   reads a form's input and stores it as a javascript
 *   object accessible through `req.body`
 *
 */
var bodyParser = require('body-parser');

/**
 * Flash messages for passport
 *
 * Setting the failureFlash option to true instructs Passport to flash an
 * error message using the message given by the strategy's verify callback,
 * if any. This is often the best approach, because the verify callback
 * can make the most accurate determination of why authentication failed.
 */
var flash = require('express-flash');

// attempt to build the providers/passport config
var config = {};
try {
    config = require('../providers.json');
} catch (err) {
    console.trace(err);
    process.exit(1); // fatal
}

// -- Add your pre-processing middleware here --

// Setup the view engine (jade)
var path = require('path');
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// boot scripts mount components like REST API
boot(app, __dirname);

// to support JSON-encoded bodies
app.middleware('parse', bodyParser.json());
// to support URL-encoded bodies
app.middleware('parse', bodyParser.urlencoded({
    extended: true,
}));

// The access token is only available after boot
app.middleware('auth', loopback.token({
    model: app.models.accessToken,
}));

console.log(loopback.token({
    model: app.models.accessToken,
}));

app.middleware('session:before', cookieParser(app.get('cookieSecret')));
app.middleware('session', session({
    secret: 'kitty',
    saveUninitialized: true,
    resave: true,
}));
passportConfigurator.init();

// We need flash messages to see passport errors
app.use(flash());

console.log(app.models.user);
console.log(app.models.userIdentity);
console.log(app.models.UserCredential);

passportConfigurator.setupModels({
    userModel: app.models.user,
    userIdentityModel: app.models.userIdentity,
    userCredentialModel: app.models.UserCredential,
});

for (var s in config) {
    var c = config[s];
    c.session = c.session !== false;
    passportConfigurator.configureProvider(s, c);
}
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

app.get('/', function (req, res, next) {
    res.render('pages/index', {
        user:
        req.user,
        url: req.url,
    });
});

app.get('/auth/account', ensureLoggedIn('/login'), function (req, res, next) {
    res.status(200).json({ "message": req.user });
});

app.get('/local', function (req, res, next) {
    res.render('pages/local', {
        user: req.user,
        url: req.url,
    });
});

app.get('/login', function (req, res, next) {
    res.render('pages/login', {
        user: req.user,
        url: req.url,
    });
});
app.get('/taco', function (req, res, next) {
    console.log("cdsajuhkvhdsukbjksedvdfscVDSJLXB DFSOUCVBCoxujb dhsyuxzbv udsbhuil")
    res.status(200).json("message");
});

app.get('/auth/logout', function (req, res, next) {
    req.logout();
    res.redirect('/');
});



var loopback = require('loopback');
var User = loopback.User; // Getting User model

app.post('/my/login', function (req, res) {
    User.login({
        email: "maadmin@meetmaestro.com",
        password: "pass"
    }, 'user', function (err, token) {
        if (err) {
            res.render('response', { //render view named 'response.ejs'
                title: 'Login failed',
                content: err,
                redirectTo: '/',
                redirectToLinkText: 'Try again'
            });
            return;
        }
        console.log('accessToken', token)
        res.status(200).json({ 'accessToken': token })

    });
});


var passport = require('passport');
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions


// require('./config/passport').default(passport, app);
// lib
var passportLocal = require('passport-local');
var loopback = require('loopback');

// app
var config = require('./config');
var redis = require("redis");
var client = redis.createClient();
var jwt = require('jsonwebtoken'),
    LocalStrategy = require('passport-local').Strategy,
    BearerStrategy = require('passport-http-bearer').Strategy;

passport.use('blah', new passportLocal.Strategy({
    usernameField: 'email'
},
    function (email, password, cb) {
        console.log('passportLocal.Strategy')


        var User = loopback.User; // Getting User model

        User.login({
            email: "maadmin@meetmaestro.com",
            password: "pass"
        }, 'user', function (err, token) {
            if (err) {
                res.render('response', { //render view named 'response.ejs'
                    title: 'Login failed',
                    content: err,
                    redirectTo: '/',
                    redirectToLinkText: 'Try again'
                });
                return;
            }
            console.log('accessToken', token)
            // res.status(200).json({ 'accessToken':    })
            return cb(null, { "name": "Ima user", "id": 9879, "email": "fake@email.com", "token": token });

        });



    }));

passport.use(new BearerStrategy(function (token, cb) {
    console.log('BearerStrategy')
    jwt.verify(token, 'verySecret', function (err, decoded) {
        console.log('verify')
        if (err) {
            console.log(err)
            return cb(err);
        }
        console.log('no err')
        client.get(token, function (err, user) {
            console.log('redis ')
            if (err) return cb(err);
            console.log('no redis error')
            return cb(null, user ? JSON.parse(user) : false);
        });
    });
}));



app.post('/jwt/login', function (req, res, next) {

    var jwt = require('jsonwebtoken');

    var client = redis.createClient();
    console.log('calluing authenticate')
    passport.authenticate('blah', { session: false }, function (err, user, info) {
        if (err) return next(err);
        if (!user) {
            return res.status(401).json({ status: 'error', code: 'Invalid Username or Password' });
        } else {
            var token = jwt.sign({ id: user.id, email: user.email }, 'verySecret');
            res.cookie('access_token', token, { httpOnly: true });
            client.set(token, JSON.stringify(user));
            return res.status(200).json({ access_token: token });
        }
    })(req, res, next);
});



app.start = function () {

    app.use(loopback.token({
        model: app.models.accessToken,
        currentUserLiteral: 'me'
    }));

    return app.listen(function () {
        app.emit('started');
        var baseUrl = app.get('url').replace(/\/$/, '');
        console.log('Web server listening at: %s', baseUrl);
        if (app.get('loopback-component-explorer')) {
            var explorerPath = app.get('loopback-component-explorer').mountPath;
            console.log('Browse your REST API at %s%s', baseUrl, explorerPath);
        }

        // All routes from this point on need to authenticate with bearer:
        // Authorization: Bearer <token here>
        app.all('/taco/*', function (req, res, next) {
            if (req.cookies && req.cookies.access_token) {
                req.headers['authorization'] = 'bearer ' + req.cookies.access_token;
            }

            console.log('req.headers');
            console.log(req.headers);
            console.log('req.headers');
            passport.authenticate('bearer', { session: false }, function (err, user, info) {
                if (err) return next(err);
                console.log(user)
                if (user) {
                    req.user = user;
                    return next();
                } else {
                    return res.status(401).json({ status: 'error', code: 'Unauthorized' });
                }
            })(req, res, next);
        });
        app.get('/taco/2', function (req, res, next) {
            console.log("req.user cdsajuhkvhdsukbjksedvdfscVDSJLXB DFSOUCVBCoxujb dhsyuxzbv udsbhuil")
            console.log(req.user)
            console.log("req.user cdsajuhkvhdsukbjksedvdfscVDSJLXB DFSOUCVBCoxujb dhsyuxzbv udsbhuil")
            res.status(200).json("message");
        });
    });
};

if (require.main === module) {
    app.start();
}
