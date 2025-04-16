import { Strategy as PassportCasStrategy } from "@coursetable/passport-cas";

/**
 * @param {Object}  casProperties 
 * @param {("CAS1.0"|"CAS2.0"|"CAS2.0-with-saml"|"CAS3.0"|"CAS3.0-with-saml")=} casProperties.version
 * @param {String}  casProperties.casBaseURL
 * @param {String=} casProperties.serviceBaseURL
 */
export default function strategy(casProperties) {
    if (CAS.casBaseURL.endsWith('/')) {
        CAS.casBaseURL = CAS.casBaseURL.slice(0, -1);
    }

    const passportCasOpts = {
        version: casProperties.version,
        ssoBaseURL: casProperties.casBaseURL,
        serverBaseURL: casProperties.serviceBaseURL,
    };

    return {
        name: "cas",
        strategy: new PassportCasStrategy(passportCasOpts, function(profile, done) {
            return done(null, {
                uid:        profile.user,
                attributes: profile.attributes,
                profile:    profile
            });
        })
    };
}
