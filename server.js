const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const oauth2orize = require("oauth2orize");
const { engine: handlebars } = require("express-handlebars");
const passport = require("./passport");
const path = require("path");
const models = require("./models");
const crypto = require("crypto");
const fs = require("fs-extra");
const cors = require("cors");

const app = express();
const server = oauth2orize.createServer();

app.use("/assets", express.static(path.join(__dirname, "assets")));
app.engine(".hbs", handlebars({ extname: ".hbs" }));
app.set("view engine", ".hbs");
app.set("views", "./views");
app.use(
    session({ secret: "oauth-secret", resave: false, saveUninitialized: false })
);
app.use(bodyParser.json({ extended: false }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(
    cors({
        origin: function (origin, callback) {
            if ([undefined, null, "null", "undefined"].includes(origin))
                return callback(null, true);

            if (models.clients.find((t) => t.redirectUri.includes(origin))) {
                return callback(null, true);
            }

            return callback(
                new Error("CORS not allowed from this origin: " + origin),
                false
            );
        },
        credentials: true,
    })
);

app.post("/login", passport.authenticate("local"), (req, res) => {
    const redirectTo = req.body.returnTo || req.session.returnTo || "/";
    console.log("/login", {
        redirectTo,
        user: req.user,
    });
    res.redirect(redirectTo);
});

app.get("/logout", (req, res) => {
    req.logout(() => {
        req.session.destroy((err) => {
            const redirectUri = req.query.redirect_uri || "/login";
            if (err) {
                console.error("Logout error:", err);
                return res.redirect("/login");
            }
            res.redirect(redirectUri);
        });
    });
});

function ensureLoggedIn(req, res, next) {
    console.log("ensureLoggedIn", req.originalUrl);
    if (req.isAuthenticated()) {
        return next();
    }

    let returnTo = req.originalUrl;
    console.log({ returnTo });
    if (returnTo.includes("/accounts")) {
        returnTo = returnTo.replace("/accounts", "/authorize");
    }
    res.render("login", {
        returnTo,
    });
}

function logRequest(req, res, next) {
    console.log("logRequest", {
        originalUrl: req.originalUrl,
        method: req.method,
        body: req.body,
        query: req.query,
        headers: req.headers,
        params: req.params,
    });
    return next();
}

server.grant(
    oauth2orize.grant.code((client, redirectUri, user, ares, done) => {
        console.log("server.grant", { client, redirectUri, user, ares });
        const code = crypto.randomBytes(16).toString("hex");
        models.authCodes.push({
            code,
            clientId: client.clientId,
            redirectUri,
            userId: user.id,
        });
        done(null, code);
    })
);

server.exchange(
    oauth2orize.exchange.password(
        async (client, username, password, scope, done) => {
            const user = models.users.find(
                (u) => u.username === username && u.password === password
            );

            if (!user) {
                return done(null, false); // invalid login
            }

            const accessToken = crypto.randomBytes(32).toString("hex");
            const refreshToken = crypto.randomBytes(32).toString("hex");

            models.tokens.push({
                accessToken,
                refreshToken,
                userId: user.id,
                clientId: client.clientId,
            });

            return done(null, accessToken, refreshToken, { expires_in: 3600 });
        }
    )
);

server.exchange(
    oauth2orize.exchange.code((client, code, redirectUri, done) => {
        console.log("server.exchange.code ", { client, redirectUri, code });
        const authCode = models.authCodes.find(
            (c) => c.code === code && c.clientId === client.clientId
        );
        if (!authCode || authCode.redirectUri !== redirectUri)
            return done(null, false);

        const accessToken = crypto.randomBytes(32).toString("hex");
        const refreshToken = crypto.randomBytes(32).toString("hex");

        models.tokens.push({
            accessToken,
            refreshToken,
            userId: authCode.userId,
            clientId: authCode.clientId,
        });

        done(null, accessToken, refreshToken, { expires_in: 3600 });
    })
);

server.exchange(
    oauth2orize.exchange.refreshToken(async (client, refreshToken, done) => {
        const token = models.tokens.find(
            (t) => t.refreshToken === refreshToken
        );

        console.log("server.exchange.refreshToken ", {
            client,
            refreshToken,
            token,
        });
        if (!token || token.clientId !== client.clientId) {
            return done(null, false);
        }

        const user = models.users.find((t) => t.id == token.userId);
        const newAccessToken = crypto.randomBytes(32).toString("hex");
        const newRefreshToken = crypto.randomBytes(32).toString("hex");

        models.tokens.push({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
            userId: token.userId,
            clientId: token.clientId,
        });
        return done(null, newAccessToken, newRefreshToken, {
            expires_in: 3600,
        });
    })
);

server.serializeClient((client, done) => {
    return done(null, client.id);
});

server.deserializeClient((id, done) => {
    const client = models.clients.find((c) => c.id === id);
    if (!client) return done(new Error("Client not found"));
    return done(null, client);
});

app.get(
    "/accounts",
    ensureLoggedIn,

    async (req, res) => {
        console.log("Request Data =>", req?.user);
        res.render("accounts", {
            user: req.user,
        });
    }
);

// /authorize endpoint
app.get(
    "/authorize",
    ensureLoggedIn,
    server.authorize((clientId, redirectUri, done) => {
        console.log("server.authorize request", clientId, redirectUri);
        const client = models.clients.find((c) => c.clientId === clientId);
        return client && client.redirectUri === redirectUri
            ? done(null, client, redirectUri)
            : done(null, false);
    }),
    async (req, res) => {
        console.log("server.authorize done", { oauth2: req.oauth2 });
        res.render("consent", {
            transactionID: req.oauth2.transactionID,
        });
    }
);

app.post("/authorize/decision", ensureLoggedIn, server.decision());

// /token endpoint
app.post(
    "/token",
    logRequest,
    passport.authenticate(["basic", "oauth2-client-password"], {
        session: false,
    }),
    server.token(),
    server.errorHandler()
);

app.get(
    "/user",
    logRequest,
    passport.authenticate("bearer", { session: false }),
    (req, res, next) => {
        res.send(req.user);
    }
);

app.get(
    "/client",
    logRequest,
    passport.authenticate("bearer", { session: false }),
    (req, res, next) => {
        console.log(req.session);
        res.send(req.user.client);
    }
);

//SSO Endpoints
app.get("/auth/saml", passport.authenticate("saml"));

app.post(
    "/auth/saml/callback",
    passport.authenticate("saml", {
        failureRedirect: "/login",
        failureFlash: true,
    }),
    (req, res) => {
        console.log("SAML login successful", req.user);
        const code = crypto.randomBytes(16).toString("hex");
        models.authCodes.push({
            code,
            clientId: "test",
            redirectUri: "http://localhost:4113/dev-portal/",
            userId: req.user.id,
        });
        const url =
            "http://localhost:4113/dev-portal/authorize-login?code=" + code;
        console.log({ url });
        res.redirect(url);
    }
);

app.listen(4000, () =>
    console.log("OAuth2 Server running on http://localhost:4000")
);
