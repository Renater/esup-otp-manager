import { Server as SocketServer } from "socket.io";
let io;
let sharedSession;
import SharedSession from 'express-socket.io-session';
import * as apiSockets from '../client/sockets.js';

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

function initialize(){
    io.on("connection", function(socket) {
        if(socket.handshake.session.passport){
            if(!socket.handshake.session.passport.user) {
                socket.disconnect('Forbidden');
                return;
            }
            apiSockets.userConnection(socket.handshake.session.passport.user.uid, socket.id);

            socket.on('disconnect', function () {
                apiSockets.userDisconnection(socket.id);
            })
        }
    });
}

export function emit(socket, emit, data) {
    io.to(socket).emit(emit, data);
}
