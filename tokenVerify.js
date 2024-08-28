const express = require('express');
const jwt = require('jsonwebtoken');
const { data } = require('./data.json')


const jwtMiddleware = (req, res, next) => {
    const authHeader = req.headers["authorization"]
    if (!authHeader) {
        return res.status(401).send('unauthorised')
    }

    const tokenName = authHeader.split(' ')[1]

    if (!tokenName) {
        return res.status(404).send('token invaild')
    }

    jwt.verify(tokenName, 'secretKey',

        (err, decoded) => {
            if (err) {
                console.error(err);
                return res.status(404).send('invalid token');
            }
            const queryUsername = req.body.username;
            if (decoded.username !== queryUsername) {
                return res.status(403).send('Username does not match token');
            }

            // Store the username in the request object for later use


            req.body.email = decoded.email;

            next();
        });

}
module.exports = jwtMiddleware;
