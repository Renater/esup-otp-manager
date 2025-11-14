/**
 * @import { Room } from "socket.io-adapter"
 *
 * @type { Object.<String:Set<Room>>}
 */
const userSockets = {};

/** @returns {?Set<Room>} */
export function get(uid) {
    return userSockets[uid];
}

export function add(uid, idSocket) {
    (userSockets[uid] ||= new Set())
        .add(idSocket);
}

export function del(uid, idSocket) {
    userSockets[uid]?.delete(idSocket);

    // delete Set if now empty
    if (!userSockets[uid]?.size) {
        delete userSockets[uid];
    }
}
