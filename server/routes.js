var express = require('express');
var router = express.Router();
var properties = require(__dirname+'/../properties/properties');
var utils = require(__dirname+'/../services/utils');
const apiRoutes = require('./routes/apiRoutes');
const isUser = apiRoutes.isUser;

var passport;


function routing() {
    router.get('/api/messages', function(req, res) {
        var lang = req.acceptsLanguages('fr', 'en');
        if (lang) {
            res.json(properties["messages_" + lang]);
        } else {
            res.json(properties.messages);
        }
    });

    router.get('/api/messages/:language', isUser, function(req, res) {
        switch (req.params.language) {
            case "français": res.json(properties.messages_fr); break;
            case "english": res.json(properties.messages_en); break;
            default: res.json(properties.messages); break;
        }
    });

    router.get('/manager/users_methods', isUser, function(req, res) {
        res.send({ ...properties.esup.users_methods, user: req.user });
    });

    require('./routes/pagesRoutes').routing(router, passport);
    apiRoutes.routing(router);
}

module.exports = function(_passport) {
    passport = _passport;

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        var _user = {};
        _user.uid=user.uid;
        _user.attributes=user.attributes;
        if(utils.is_admin(user))_user.role="admin";
        else if(utils.is_manager(user))_user.role="manager";
        else _user.role="user";
        done(null, _user);
    });

    // used to deserialize the user
    passport.deserializeUser(function(user, done) {
            done(null, user);
    });

    passport.use(new(require('passport-apereo-cas').Strategy)(properties.esup.CAS, function(profile, done) {
	// console.log("profile : " + JSON.stringify(profile, null ,2));
        return done(null, {uid:profile.user, attributes:profile.attributes});
    }));

    routing();

    return router
};
