/**
 * socket.io client connected to esup-otp-api.
 */

import properties from '../properties/properties.js';
import logger from '../services/logger.js'

import io from 'socket.io-client';

const apiSockets = io(properties.esup.api_url, {reconnect: true, path: "/sockets", query: 'app=manager', extraHeaders: {
    Authorization: "Bearer " + properties.esup.api_password,
    // x-tenant: "",
}});
import * as managerSockets from '../server/sockets.js';

apiSockets.on('connect', function () {
    logger.info("Api Sockets connected");
});

const EVENTS_TO_FORWARD = ['userPushActivate', 'userPushDeactivate'];

for(const event of EVENTS_TO_FORWARD) {
    apiSockets.on(event, function(data) {
        managerSockets.emitUser(data.uid, event);
    });
}
