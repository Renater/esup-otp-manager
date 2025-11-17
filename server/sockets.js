/**
 * socket.io server connected to browsers.
 */

import { Server as SocketServer } from "socket.io";
/** @type { SocketServer } */
let io;
let sharedSession;
import SharedSession from 'express-socket.io-session';
import '../client/sockets.js';

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
            socket.join(requestedUser);
        } else {
            socket.disconnect('Forbidden');
        }
    });
}

export function emitUser(uid, event) {
    io.to(uid).emit(event);
}
