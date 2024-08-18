// app.js
const express = require('express');
const crypto = require('crypto');
const symmetricJWTMiddleware = require('./symmetricMiddleware');
const asymmetricJWTMiddleware = require('./asymmetricMiddleware');
const { readKeys } = require('./jwtUtils');
const clientPublic = process.env.CLIENT_PUBLIC;
const serverPrivate = process.env.SERVER_PRIVATE;
let secret;

const app = express();

(async () => {
    const { publicKey, privateKey } = await readKeys({publicPem: clientPublic, privatePem: serverPrivate});
    secret = crypto.createSecretKey(process.env.SHARED_SECRET);
    console.log('secret: ', secret)
    
    app.use('/symmetric', symmetricJWTMiddleware(secret));
    app.use('/asymmetric', asymmetricJWTMiddleware(publicKey, privateKey));

    app.get('/symmetric', (req, res) => {
        res.json({ message: 'Symmetric route', payload: req.jwtPayload });
    });

    app.get('/asymmetric', (req, res) => {
        res.json({ message: 'Asymmetric route', payload: req.jwtPayload });
    });

    if (require.main === module) {
        app.listen(3000, () => {
            console.log('Server running on port 3000');
        });
    }
})();

module.exports = app;
