import properties from "../properties/properties.js";

export function isAuthenticated(req) {
    return Boolean(req.session.passport?.user);
}

const supportedLanguages = Object.keys(properties)
    .filter(key => key.startsWith('messages_'))
    .map(key => key.replace('messages_', ''));

export function getMessagesForRequest(req) {
    let lang = req.acceptsLanguages(supportedLanguages) || properties.esup.default_language || "en";
    if (req.params.language && supportedLanguages.includes(req.params.language)) {
        lang = req.params.language;
    }

    return {
        messages: properties["messages_" + lang],
        lang: lang,
    };
}
