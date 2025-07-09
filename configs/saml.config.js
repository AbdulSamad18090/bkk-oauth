const fs = require("fs");
const path = require("path");

const samlConfig = {
    // --- Service Provider (SP) Config ---
    issuer: "http://localhost:4113/dev-portal", // Entity ID (use localhost for testing)
    callbackUrl: "http://localhost:4000/auth/saml/callback", // ACS URL (must match mock IdP)
    entryPoint: "https://dev-bd74irm5c4dsbwzy.us.auth0.com/samlp/vPbBrretEVvHwpJfnZC0iwS31knsVflp", // Mock IdP SSO URL (e.g., saml-idp)

    // --- Certificates (Generate self-signed for testing) ---
    cert: fs.readFileSync(path.join(__dirname, "../certificates", "localhost.pem"), "utf8"), // Public cert
    privateKey: fs.readFileSync(path.join(__dirname, "../certificates", "localhost-key.pem"), "utf8"), // Private key

    // --- SAML Behavior ---
    identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    authnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    acceptedClockSkewMs: 60000, // Allow 1min clock skew for testing
    disableRequestedAuthnContext: true, // Simplify testing
    wantAssertionsSigned: false, // Disable for mock IdP (enable in prod)
    validateInResponseTo: false // Disable for testing (enable in prod)
};

module.exports = samlConfig;
