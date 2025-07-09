const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const BasicStrategy = require("passport-http").BasicStrategy;
const ClientPasswordStrategy = require("passport-oauth2-client-password").Strategy;
const BearerStrategy = require("passport-http-bearer").Strategy;
const SamlStrategy = require("passport-saml").Strategy;
const models = require("./models");
const samlConfig = require("./configs/saml.config");

passport.use(new LocalStrategy((username, password, done) => {
    const user = models.users.find(u => u.username === username && u.password === password);
    return user ? done(null, user) : done(null, false);
}));

passport.use(new BasicStrategy(async (clientId, clientSecret, done) => {
    try {
        console.log("BasicStrategy request", clientId);
        const client = models.clients.find(t => t.clientId == clientId);
        if (!client || client.clientSecret !== clientSecret) {
            return done(new Error("Invalid client credentials"));
        }

        console.log("BasicStrategy authorized", client);
        return done(null, client);
    } catch (err) {
        return done(err);
    }
}));

passport.use(new ClientPasswordStrategy(async (clientId, clientSecret, done) => {
    try {
        console.log("ClientPasswordStrategy request", clientId);
        const client = models.clients.find(t => t.clientId == clientId);
        if (!client || client.clientSecret !== clientSecret) {
            return done(new Error("Invalid client credentials"));
        }

        console.log("ClientPasswordStrategy authorized", client);
        return done(null, client);
    } catch (err) {
        return done(err);
    }
}));

passport.use(new BearerStrategy((token, done) => {
    const tokenRecord = models.tokens.find(t => t.accessToken === token);
    console.log("BearerStrategy request", { token, list: models.tokens, tokenRecord });
    if (!tokenRecord) return done(null, false);

    const user = models.users.find(t => t.id == tokenRecord.userId);
    const client = models.clients.find(t => t.clientId == tokenRecord.clientId);

    console.log("BearerStrategy response", { client, user, tokenRecord });
    return done(null, user, { client });
}));

passport.use(new SamlStrategy(samlConfig, (profile, done) => {
    const {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": email
    } = profile;
    const user = {
        id: email || profile.nameID || profile["urn:oid:0.9.2342.19200300.100.1.3"],
        userId: email
    // name: profile.cn || profile['urn:oid:2.5.4.3'],
    };
    console.log("SAML User:", user);
    return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const user = models.users.find(u => u.id === id);
    done(null, user || false);
});

module.exports = passport;
