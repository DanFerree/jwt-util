// app.js
const express = require('express');
const symmetricJWTMiddleware = require('./symmetricMiddleware');
const asymmetricJWTMiddleware = require('./asymmetricMiddleware');
const { generateRSAKeys } = require('./jwtUtils');

const app = express();
const secret = 'your-256-bit-secret';

(async () => {
    const { publicKey, privateKey } = await generateRSAKeys();

    app.use('/symmetric', symmetricJWTMiddleware(secret));
    app.use('/asymmetric', asymmetricJWTMiddleware(publicKey, privateKey));

    app.get('/symmetric', (req, res) => {
        res.json({ message: 'Symmetric route', payload: req.jwtPayload });
    });

    app.get('/asymmetric', (req, res) => {
        res.json({ message: 'Asymmetric route', payload: req.jwtPayload });
    });

    app.listen(3000, () => {
        console.log('Server running on port 3000');
    });
})();
