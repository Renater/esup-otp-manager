import properties from '../../properties/properties.js';
import * as utils from '../../services/utils.js';
import logger from '../../services/logger.js';
const tenants = require(__dirname + '/../tenants');

function isUser(req, res, next) {
    if (utils.isAuthenticated(req)) return next();
    res.redirect('/login'); // can't use 401 because of https://www.rfc-editor.org/rfc/rfc7235#section-3.1 (302 is used by default)
}

export function routing(router, passport) {
    router.get('/', function(req, res) {
        const reqMessages = utils.getMessagesForRequest(req);
        res.render('index', {
            title: 'ESUP OTP Manager',
            messages: reqMessages.messages,
            lang: reqMessages.lang
        });
    });

    router.get('/forbidden', isUser, function(req, res) {
        res.render('forbidden', {
            title: 'Esup Otp Manager',
            user: req.session.passport.user
        });
    });

    router.get('/preferences', isUser, function(req, res) {
        res.render('dashboard', {
            title: 'Esup Otp Manager : Test',
            user: req.session.passport.user,
            right: req.session.passport.user.role
        });
    });

    function log_user(req, res, next, user) {
        req.logIn(user, function(err) {
            if (err) {
                logger.error(err);
                return next(err);
            }
            req.session.messages = '';

            let params = new URLSearchParams()
            for (const param of ['user']) {
                const val = req.query[param]
                if (val) params.set(param, val)
            }
            return res.redirect('/preferences' + (params.size ? "?" + params : ""));
        });
    };

    if (properties.strategy.name == 'cas') {
        router.all('/login', function(req, res, next) {
            passport.authenticate('cas', function(err, user, info) {
                if (err) {
                    logger.error(err);
                    return next(err);
                }

                if (!user) {
                    console.log(info.message);
                    return res.redirect('/');
                }

                return log_user(req, res, next, user);
            })(req, res, next);
        });

        router.get('/logout', function(req, res, next) {
            req.logout(function(err) {
                if (err) { return next(err); }
                res.redirect(properties.esup.CAS.casBaseURL + 'logout');
            });
        });
    } else if (properties.strategy.name == 'saml') {

        async function getUserLastValidation(user) {
            const tenant = user.attributes.issuer;
            const password = await tenants.getApiPassword(tenant);
            console.log('tenant: ' + tenant);
            console.log('password: ' + password);

            const response = await fetch(properties.esup.api_url + '/protected/users/' + user.uid, {headers: {
                'Content-Type': 'application/json',
                'X-Tenant': tenant,
                'Authorization':  'Bearer ' + password
            }});
            const data = await response.json();
            return data.user.last_validated;
        }

        async function logOrReauthUser(req, res, next, user) {
            const result = await getUserLastValidation(user);
            if ('time' in result) {
                const assertion = user.attributes.getAssertion();
                const context = assertion.Assertion.AuthnStatement[0].AuthnContext[0].AuthnContextClassRef[0]._;
                if (context == properties.esup.SAML.normalAuthnContext) {
                    return log_user(req, res, next, user);
                } else {
                    let params = new URLSearchParams();
                    params.set('authnContext', properties.esup.SAML.normalAuthnContext);
                    return res.redirect('/login' + "?" + params);
                }
            } else {
                return log_user(req, res, next, user);
            }
        }

        router.get('/login', function(req, res, next) {
            passport.authenticate('saml')(req, res, next);
        });

        router.post('/login', function(req, res, next) {
            passport.authenticate('saml', function(err, user, info) {
                if (err) {
                    console.log(err);
                    return next(err);
                }

                if (!user) {
                    console.log(info.message);
                    return res.redirect('/');
                }

                return logOrReauthUser(req, res, next, user);
            })(req, res, next);
        });

        router.get('/logout', function(req, res, next) {
            properties.strategy.strategy.logout(req, (err, logoutUrl) => {
                if (err) { return next(err); }
                req.logout(function(err) {
                    if (err) { return next(err); }
                    res.redirect(logoutUrl);
                });
            });
        });

        const spMetadataUrl = properties.esup.SAML.spMetadataUrl;
        if (spMetadataUrl) {
            router.get("/" + spMetadataUrl, function(req, res, next) {
                properties.strategy.generateMetadata(req, res, next);
            });
        }
    }
}
