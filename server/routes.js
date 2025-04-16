import express from 'express';
const router = express.Router();
import properties from '../properties/properties.js';
import * as utils from '../services/utils.js';
import * as aclUtils from '../services/aclUtils.js';
import * as apiRoutes from './routes/apiRoutes.js';
const isUser = apiRoutes.isUser;
import * as pagesRoutes from './routes/pagesRoutes.js';
import logger from '../services/logger.js';
import { Strategy as CasStrategy } from '@coursetable/passport-cas';

let passport;


function routing() {
    router.get('/status', function(req,res) {
        res.status(200);
        res.send({
            code: 'Ok'
        });
    });

    router.get('/manager/messages/{:language}', isUser, function(req, res) {
        res.json(utils.getMessagesForRequest(req));
    });

    router.get('/manager/users_methods', isUser, function(req, res) {
        res.send({ unauthorized: aclUtils.getUnauthorizedMethods(req.user) });
    });

    router.get('/manager/infos', isUser, function(req, res) {
        res.send({
            api_url: properties.esup.api_url,
            uid: req.session.passport.user.uid,
            name: req.session.passport.user.name,
            transport_regexes: properties.esup.transport_regexes,
        });
    });

    pagesRoutes.routing(router, passport);
    apiRoutes.routing(router);
}

export default async function(_passport) {
    passport = _passport;

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        const _user = {};
        _user.uid=user.uid;
        _user.name=user.name;
        _user.attributes=user.attributes;
        aclUtils.prepareUserForAcl(_user);
        if (aclUtils.is_admin(user)) _user.role = "admin";
        else if (aclUtils.is_manager(user)) _user.role = "manager";
        else _user.role = "user";
        done(null, _user);
    });

    // used to deserialize the user
    passport.deserializeUser(function(user, done) {
        done(null, user);
    });

    if (properties.esup.CAS) {
        const { default: casStrategy } = await import('./strategies/casStrategy.mjs');
        properties.strategy = await casStrategy(properties.esup.CAS);
    } else if (properties.esup.SAML) {
        const { default: samlStrategy } = await import('./strategies/samlStrategy.mjs');
        properties.strategy = await samlStrategy(properties.esup.SAML);
    } else {
        throw new Error("No strategy defined in esup.properties");
    }

    passport.use(properties.strategy.strategy);

    routing();

    return router
}
