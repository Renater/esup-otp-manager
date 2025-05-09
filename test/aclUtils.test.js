import { before, describe, it } from "node:test";
import assert from "node:assert"

import { normalizeEsupProperties, is_admin, is_manager, is_authorized, prepareUserForAcl } from '../services/aclUtils.js';
import properties from "../properties/properties.js";
const { esup } = properties;

describe("aclUtils", () => {
    describe("normalizeEsupProperties", () => {
        it("Only one filter between 'deny' and 'allow' can be defined by users_method", () => {
            esup.users_methods.random_code = {
                allow: { "memberof": ["cn=esup-otp.random_code_mail,ou=groups,dc=univ-ville,dc=fr"] },
                deny: { "memberof": ["cn=esup-otp.not_random_code,ou=groups,dc=univ-ville,dc=fr"] }
            };

            assert.throws(() => normalizeEsupProperties());
        });
    });

    describe("acl tests", () => {
        before(() => {
            esup.admins = ["john"];
            esup.admins_attributes = { "memberof": "cn=esup-otp.admin,ou=groups,dc=univ-ville,dc=fr" };
            esup.managers = ["paul"];
            esup.managers_attributes = { "supannentiteaffectation": ["manager", "DSI"] };
            esup.users_methods = {
                "random_code": { "deny": { "edupersonaffiliation": ["student", "alum"], "memberof": ["cn=esup-otp.NOT_random_code,ou=groups,dc=univ-ville,dc=fr"] } },
                "random_code_mail": { "allow": { "edupersonaffiliation": ["student", "alum"], "memberof": ["cn=esup-otp.random_code_mail,ou=groups,dc=univ-ville,dc=fr"] } },
                "bypass": { "allow": { "memberof": ["cn=esup-otp.bypass,ou=groups,dc=univ-ville,dc=fr"] } }
            };
            normalizeEsupProperties();
        });

        const paul = {
            uid: "paul",
            attributes: {
                "memberof": ["cn=esup-otp.not_RANDOM_CODE,ou=groups,dc=univ-ville,dc=fr"]
            }
        };
        const john = {
            uid: "john",
            attributes: {
                "supannentiteaffectation": ["staff", "DSI"],
                "edupersonaffiliation": ["alum"],
            }
        };
        const toto = {
            uid: "toto",
            attributes: {
                "memberof": ["cn=esup-OTP.admin,ou=groups,dc=univ-ville,dc=fr"],
                "toto": ["manager"],
            }
        };
        const tata = {
            uid: "tata",
            attributes: {
                "supannentiteaffectation": ["DSI"],
                "memberof": ["cn=esup-otp.random_code_mail,ou=groups,dc=univ-ville,dc=fr"],
            }
        };

        const users = [paul, john, toto, tata];
        before(() => {
            for (const user of users) {
                prepareUserForAcl(user);
            }
        });

        it("is_admin", () => {
            assert(!is_admin(paul));
            assert(is_admin(john), "esup.admins");
            assert(is_admin(toto), "memberof: cn=esup-otp.admin,ou=groups,dc=univ-ville,dc=fr");
            assert(!is_admin(tata));
        });

        it("is_manager", () => {
            assert(is_manager(paul), "esup.managers");
            assert(is_manager(john), "supannentiteaffectation: DSI");
            assert(!is_manager(toto));
            assert(is_manager(tata));
        });

        it("is_authorized", () => {
            for (const user of users) {
                assert(is_authorized(user, "webauthn"));
            }

            assert(!is_authorized(paul, "random_code"));
            assert(!is_authorized(john, "random_code"));
            assert(is_authorized(toto, "random_code"));
            assert(is_authorized(tata, "random_code"));

            assert(!is_authorized(paul, "random_code_mail"));
            assert(is_authorized(john, "random_code_mail"));
            assert(!is_authorized(toto, "random_code_mail"));
            assert(is_authorized(tata, "random_code_mail"));

            for (const user of users) {
                assert(!is_authorized(user, "bypass"));
            }
        });
    });
});

