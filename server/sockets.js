/**
 * socket.io server connected to browsers.
 */

import { Server as SocketServer } from "socket.io";
/** @type { SocketServer } */
let io;
let sharedSession;
import SharedSession from 'express-socket.io-session';
import '../client/sockets.js';
import * as userSockets from '../services/userSockets.js';

export function attach(server) {
    io = new SocketServer(server, {path: "/sockets"});
    io.use(SharedSession(sharedSession, {
        autoSave:true
    }));
    initialize();
}

export function setSharedSession(session) {
    sharedSession = session;
}

function initialize() {
    io.on("connection", function(socket) {
        const loggedInUser = socket.handshake.session.passport?.user.uid;
        const requestedUser = socket.handshake.query.uid;

        if (loggedInUser && requestedUser &&
            (loggedInUser === requestedUser || socket.handshake.session.passport.user.isManager)
        ) {
            userSockets.add(requestedUser, socket.id);
            socket.on('disconnect', function() {
                userSockets.del(requestedUser, socket.id);
            })
            return;
        }
        socket.disconnect('Forbidden');
    });
}

export function emitUser(uid, event) {
    const sockets = userSockets.get(uid);
    if (sockets) {
        io.to(Array.from(sockets)).emit(event);
    }
}
