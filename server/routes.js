var express = require('express');
var router = express.Router();
var properties = require(__dirname+'/../properties/properties');
var utils = require(__dirname+'/../services/utils');
const { request } = require('undici');

var passport;


/** @param {{ relUrl: string; bearerAuth?: true, method?: 'GET'|'POST'|'PUT'|'DELETE' }} opts_ */
async function request_otp_api(req, res, opts_) {
    console.log("requesting api");
    const clientIP = req.ip;
    const userAgent = req.headers['user-agent'];
    /**
     * @typedef {import('undici').Dispatcher.RequestOptions} RequestOptions
     * @type {Omit<RequestOptions, 'origin' | 'path'>}
     */
    let opts = {
        method: opts_.method || 'GET',
    }

    if (req.body && Object.keys(req.body).length) {
        opts.body = JSON.stringify(req.body);
    }
    
    const url = properties.esup.api_url + opts_.relUrl;

    opts.headers = {
        'X-Client-IP': clientIP,
        'Client-User-Agent': userAgent,
        'Content-Type': 'application/json'
    };

    if (opts_.bearerAuth) {
        opts.headers.Authorization = 'Bearer ' + properties.esup.api_password;
    }

    //console.log(opts.method +':'+ opts.url);
    //console.log(req.session.passport);
    let response;
    try {
        response = await request(url, opts);
    } catch (error) {
        res.status(503);
        return res.send({
            "code": "Error",
            "message": error.message || "Api did not give a response"
        });
    }
    
    
    // forward the status code, because if the request failed
    // it should not be responding with 200 ("everything is fine !")
    //
    // this helps to have clearer error messages, because getting
    // "error, code 200" with a message containing just "Error" is
    // kind of frustrating.
    res.status(response.statusCode);
    /** @type {Object} */
    const infos = await response.body.json();
    if (req.session.passport.user.uid) infos.uid = req.session.passport.user.uid;
    infos.api_url = properties.esup.api_url;
    //console.log(infos)
    res.send(infos);
}

function isAuthenticated(req, res) {
    if (req.session.passport) {
        if (req.session.passport.user) {
            return true;
        }
    }
    return false;
}

function isUser(req, res, next) {
    if (isAuthenticated(req, res)) return next();
    res.redirect('/login');
}

function isManager(req, res, next) {
    if (isAuthenticated(req, res)) {
        if (utils.is_manager(req.session.passport.user) || utils.is_admin(req.session.passport.user))return next();
        res.redirect('/forbidden');
    }
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    if (isAuthenticated(req, res)) {
        if(utils.is_admin(req.session.passport.user))return next();
        res.redirect('/forbidden');
    }
    res.redirect('/login');
}

/**
 * @returns hash for current user
 */
function getHash(req) {
    return utils.get_hash(req.session.passport.user.uid);
}

function routing() {
    router.get('/', function(req, res) {
        res.render('index', {
            title: 'Esup Otp Manager',
            messages : properties.messages
        });
    });

    router.get('/forbidden', isUser, function(req, res) {
        res.render('forbidden', {
            title: 'Esup Otp Manager',
            user: req.session.passport.user
        });
    });

    router.get('/preferences', isUser, function(req, res) {
        var right = "user";
        if (utils.is_manager(req.session.passport.user))right = "manager";
        if (utils.is_admin(req.session.passport.user))right = "admin";
        res.render('dashboard', {
            title: 'Esup Otp Manager : Test',
            user: req.session.passport.user,
            right : right
        });
    });

    router.get('/login', function(req, res, next) {
        passport.authenticate('cas', function(err, user, info) {
            if (err) {
                console.log(err);
                return next(err);
            }

            if (!user) {
                console.log(info.message);
                return res.redirect('/');
            }

            req.logIn(user, function(err) {
                if (err) {
                    console.log(err);
                    return next(err);
                }
                req.session.messages = '';
                return res.redirect('/preferences');
            });
        })(req, res, next);
    });

    router.get('/logout', function(req, res, next) {
        req.logout(function(err) {
            if (err) { return next(err); }
            res.redirect(properties.esup.CAS.casBaseURL+'/logout');
          });
    });

    //API
    router.get('/api/user', isUser, function(req, res) {
        request_otp_api(req, res, {
            relUrl: 'users/' + req.session.passport.user.uid + '/' + getHash(req),
        });
    });
    
    router.get('/api/messages', function(req, res) {
        var lang = req.acceptsLanguages('fr', 'en');
        if(lang) {
            res.json(properties["messages_" + lang]); 
        } else {
            res.json(properties.messages);
        }
    });
    
    router.get('/api/messages/:language', isUser, function(req, res) {
            switch (req.params.language){
                case "français": res.json(properties.messages_fr); break;
                case "english": res.json(properties.messages_en); break;
                default : res.json(properties.messages); break;
            }
    });

    router.get('/manager/users_methods', isUser, function(req, res) {
        var data = new Object();
        data=properties.esup.users_methods;
        data.user=req.user;
        res.send(data);
    });

    router.get('/api/methods', isUser, function(req, res) {
        request_otp_api(req, res, {
            relUrl: 'protected/methods/', bearerAuth: true,
        });
    });

    router.put('/api/:method/activate', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'users/'+req.session.passport.user.uid+'/methods/'+req.params.method+'/activate/' + getHash(req),
        });
    });
    
    router.post('/api/:method/activate/confirm/:activation_code', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: 'users/' + req.session.passport.user.uid + '/methods/' + req.params.method + '/activate/' + req.params.activation_code + '/' + getHash(req),
        });
    });
    
    router.post('/api/admin/:method/activate/confirm/:activation_code/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: 'protected/users/' + req.params.uid + '/methods/' + req.params.method + '/activate/' + req.params.activation_code, bearerAuth: true
        });
    });

    router.post('/api/:method/confirm_activate', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: 'users/' + req.session.passport.user.uid + '/methods/' + req.params.method + '/confirm_activate/' + getHash(req),
        });
    });

    router.post('/api/:method/auth/:authenticator_id', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: `users/${req.session.passport.user.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/${getHash(req)}`,
        });
    });

    router.delete('/api/:method/auth/:authenticator_id', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: `users/${req.session.passport.user.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/${getHash(req)}`,
        });
    });
    
    router.post('/api/admin/:method/confirm_activate/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: 'protected/users/' + req.params.uid + '/methods/' + req.params.method + '/confirm_activate/', bearerAuth: true,
        });
    });

    router.post('/api/admin/:method/auth/:authenticator_id/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: `protected/users/${req.params.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/`, bearerAuth: true,
        });
    });

    router.delete('/api/admin/:method/auth/:authenticator_id/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: `protected/users/${req.params.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/`, bearerAuth: true,
        });
    });

    router.put('/api/:method/deactivate', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'users/'+req.session.passport.user.uid+'/methods/'+req.params.method+'/deactivate/' + getHash(req),
        });
    });

    router.put('/api/transport/:transport/:new_transport', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'users/'+ req.session.passport.user.uid +'/transports/'+req.params.transport+'/'+req.params.new_transport+'/' + getHash(req),
        });
    });

    router.put('/api/admin/transport/:transport/:new_transport/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'protected/users/'+ req.params.uid +'/transports/'+req.params.transport+'/'+req.params.new_transport+'/', bearerAuth: true,
        });
    });

    router.get('/api/transport/:transport/:new_transport/test', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'GET',
            relUrl: 'users/' + req.session.passport.user.uid + '/transports/' + req.params.transport + '/' + req.params.new_transport + '/test/' + getHash(req),
        });
    });

    router.get('/api/admin/transport/:transport/:new_transport/test/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'GET',
            relUrl: 'protected/users/' + req.params.uid + '/transports/' + req.params.transport + '/' + req.params.new_transport + '/test', bearerAuth: true,
        });
    });

    router.delete('/api/transport/:transport/', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: 'users/'+ req.session.passport.user.uid +'/transports/'+req.params.transport+'/' + getHash(req),
        });
    });

    router.delete('/api/admin/transport/:transport/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: 'protected/users/'+ req.params.uid +'/transports/'+req.params.transport+'/', bearerAuth: true,
        });
    });

    router.post('/api/generate/:method', isUser, function(req, res) {
        var uri = 'users/'+ req.session.passport.user.uid + '/methods/' + req.params.method + '/secret/' + getHash(req);
        if(req.query.require_method_validation === 'true') {
            uri += '?require_method_validation=true';
        }
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: uri,
        });
    });

    router.get('/api/admin/users', isManager, function(req, res) {
        request_otp_api(req, res, {
            relUrl: 'admin/users/', bearerAuth: true,
        });
    });

    router.get('/api/admin/user/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            relUrl: 'protected/users/' + req.params.uid, bearerAuth: true,
        });
    });

    router.put('/api/admin/:uid/:method/activate', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'protected/users/'+ req.params.uid + '/methods/' + req.params.method + '/activate/', bearerAuth: true,
        });
    });

    router.put('/api/admin/:uid/:method/deactivate', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'protected/users/'+ req.params.uid + '/methods/' + req.params.method + '/deactivate/', bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/activate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'admin/methods/' + req.params.method + '/activate/', bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/deactivate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'admin/methods/' + req.params.method + '/deactivate/', bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/transport/:transport/activate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'admin/methods/' + req.params.method + '/transports/'+req.params.transport+'/activate/', bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/transport/:transport/deactivate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: 'admin/methods/' + req.params.method + '/transports/'+req.params.transport+'/deactivate/', bearerAuth: true,
        });
    });

    router.post('/api/admin/generate/:method/:uid', isManager, function(req, res) {
        var uri = 'protected/users/'+ req.params.uid + '/methods/' + req.params.method + '/secret/';
        if(req.query.require_method_validation === 'true') {
            uri += '?require_method_validation=true';
        }
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: uri, bearerAuth: true,
        });
    });

    router.delete('/api/admin/delete_method_secret/:method/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: 'admin/users/'+req.params.uid +'/methods/' + req.params.method+ '/secret/', bearerAuth: true,
        });
    });
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
