import { MultiSamlStrategy } from "@node-saml/passport-saml";
import { fetch, toPassportConfig } from 'passport-saml-metadata';
import { Cache } from 'file-system-cache';
import os from 'os';
import * as utils from "../../services/utils.js";
import * as fs from 'fs';

/**
 * @param {import('@node-saml/passport-saml/lib/types').PassportSamlConfig & {printServiceProviderMetadata: boolean}} samlProperties
 */
export default async function strategy(samlProperties) {

    if (!samlProperties.identifierFormat) {
        samlProperties.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    }

    if (samlProperties.idpMetadataUrl) {
        const reader = await fetch({ url: samlProperties.idpMetadataUrl, backupStore: new Cache({ basePath: os.tmpdir() }) });

        const config = toPassportConfig(reader);
        for (const conf in config) {
            samlProperties[conf] ||= config[conf];
        }
    }

    // https://github.com/node-saml/node-saml/issues/361
    if (samlProperties.idpCert) {
        samlProperties.idpCert = samlProperties.idpCert.replace(/\s/g, '');
    }

    for (const certType of ["publicCert", "privateKey", "decryptionPvk", "decryptionPbc"]) {
        const certPathPropertyName = certType + "Path";
        const declaredPath = samlProperties[certPathPropertyName];
        if (declaredPath) {
            delete samlProperties[certPathPropertyName];
            const path = utils.resolvePath(declaredPath);

            const cert = fs.readFileSync(path).toString()
            samlProperties[certType] = cert;
        }
    }

    samlProperties['passReqToCallback'] = true;
    samlProperties['getSamlOptions'] = function (req, done) {
        var options;
        if (req.query.authnContext) {
            options = { authnContext: [ req.query.authnContext ] };
        } else {
            options = { disableRequestedAuthnContext: true };
        }
        return done(null, options);
    };

    /**
         * @param {import('@node-saml/node-saml/lib/types').Profile} profile
         * @param {import('@node-saml/passport-saml/lib/types').VerifiedCallback} done 
         */

    const samlStrategy = new MultiSamlStrategy(
        samlProperties,
        function(req, profile, done) {
            return done(null, {
                uid:        profile.attributes[samlProperties.uidSamlAttribute],
                name:       profile.attributes[samlProperties.nameSamlAttribute],
                attributes: profile.attributes,
            });
        }
    );

    return {
        name: "saml",
        strategy: samlStrategy,
        generateMetadata: function(req, res, next) {
            res.send(
                samlStrategy.generateServiceProviderMetadata(
                    req,
                    samlProperties.decryptionPbc,
                    samlProperties.publicCert,
                    function (err, data) {
                        if (err) {
                            return next();
                        }
                        res.type('xml');
                        res.send(data);
                    }
                )
            );
        }
    };
}
