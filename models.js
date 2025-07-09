const users = [
    { id: 1, username: "admin", password: "admin" }
];

const clients = [
    // { id: 3, clientId: "test", clientSecret: "test", redirectUri: "http://localhost:4113/dev-portal/" },
    { id: 1, clientId: "test", clientSecret: "test", redirectUri: "http://localhost:5500/client/index.html" },
    { id: 2, clientId: "test", clientSecret: "test", redirectUri: "http://localhost:4000" }
];

const authCodes = [];
const tokens = [];

module.exports = {
    users, clients, authCodes, tokens
};
