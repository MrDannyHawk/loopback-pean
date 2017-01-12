

// export default function(passport, app) {
// // lib
// var passportLocal = require('passport-local');
// var loopback = require('loopback');

// // app
// var config = require('./config');
//     var redis = require("redis");
//     var client = redis.createClient();
//     var jwt = require('jsonwebtoken'),
//         LocalStrategy = require('passport-local').Strategy,
//         BearerStrategy = require('passport-http-bearer').Strategy;

//     passport.use('local', new passportLocal.Strategy({
//         usernameField: 'email'
//     },
//         function (email, password, cb) {


//             var User = loopback.User; // Getting User model

//                 User.login({
//                     email: "maadmin@meetmaestro.com",
//                     password: "pass"
//                 }, 'user', function (err, token) {
//                     if (err) {
//                         res.render('response', { //render view named 'response.ejs'
//                             title: 'Login failed',
//                             content: err,
//                             redirectTo: '/',
//                             redirectToLinkText: 'Try again'
//                         });
//                         return;
//                     }
//                     console.log('accessToken', token)
//                     res.status(200).json({ 'accessToken': token })

//                 });



//         }));

//     passport.use(new BearerStrategy(function (token, cb) {
//         jwt.verify(token, 'verySecret', function (err, decoded) {
//             if (err) return cb(err);
//             client.get(token, function (err, user) {
//                 return cb(null, user ? JSON.parse(user) : false);
//             });
//         });
//     }));
// };
