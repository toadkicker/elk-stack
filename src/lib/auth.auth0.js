/**
 * Created by toadkicker on 11/10/16.
 */
var Auth0Strategy = require('passport-auth0'),
    passport = require('passport');

exports.setup = function (express, app, config) {
    console.log('Auth0 OAuth2 authentication used');

    var callbackUrl = config.host + '/authorize';
    var loginUrl = '/login/auth0';
    var loginFailUrl = '/login/fail';

    var strategy = new Auth0Strategy({
            domain: config.allowed_domain,
            clientID: config.oauth_client_id,
            clientSecret: config.oauth_client_secret,
            callbackURL: callbackUrl
        },
        function (accessToken, refreshToken, extraParams, profile, done) {
            // accessToken is the token to call Auth0 API (not needed in the most cases)
            // extraParams.id_token has the JSON Web Token
            // profile has all the information from the user
            return done(null, profile);
        }
    );
    passport.use(strategy);

    app.get(callbackUrl,
        passport.authenticate('auth0', {failureRedirect: loginUrl}),
        function (req, res) {
            if (!req.user) {
                res.redirect(loginFailUrl);
                throw new Error('user null');
            }
            res.redirect("/app/kibana");
        }
    );

    app.get(loginUrl,
        passport.authenticate('auth0', {}), function (req, res) {
            res.redirect("/");
        });

    app.get(loginFailUrl, function (req, res) {
        res.statusCode = 403;
        res.end('<html><body>Unauthorized</body></html>');
    });

    function nonAuthenticated(config, url) {
        console.log("nonauth /login/auth0", url.indexOf('/login/auth0') === 0)
        console.log("nonauth " + url, config.oauth_unauthenticated.indexOf(url) > -1)
        return url.indexOf('/login/auth0') === 0 || config.oauth_unauthenticated.indexOf(url) > -1
    }

};