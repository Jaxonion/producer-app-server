const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const router = express.Router();
const AuthService = require('./auth-service');
const { JWT_SECRET, JWT_EXPIRY } = require('../config');

const app = express()

router
    .route('/signup')
    .post((req, res, next) => {
        const { username, email, password } = req.body;
        console.log('username:', username, 'email:', email, 'password:', password)
        //res.send('successful signup')
        if (!username || !email || !password) {
            return res.status(401).json({
                error: `Missing username, email or password`
            })
        }
        const passwordError = AuthService.validatePassword(password)

        if (passwordError) {
            return res.status(400).json({ error: passwordError })
        }
        console.log('username:', username)
        AuthService.hasUserWithUserName(
            req.app.get('db'),
            username
        )
            .then(hasUserWithUserName => {
                if(hasUserWithUserName) {
                    return res.status(401).json({
                        error: 'username already being used'
                    })
                }
                AuthService.hasUserWithEmail(
                    req.app.get('db'),
                    email
                )
                    .then(hasUserWithEmail => {
                        if(hasUserWithEmail) {
                            return res.status(401).json({
                                error: 'email already being used'
                            })
                        }
                        return AuthService.hashPassword(password)
                            .then(hashedPassword => {
                                const newUser = {
                                    username,
                                    email,
                                    password: hashedPassword
                                }
                                console.log('newuserzzz', newUser)
                                return AuthService.createUser(
                                    req.app.get('db'),
                                    newUser
                                )
                                    .then(user => {
                                        res
                                            .status(201)
                                            .location(path.posix.join(req.originalUrl))
                                            .json(AuthService.serializeUser(user))
                                    })
                            })
                    })
            })
    })
    .get((req, res, next) => {
        res.send('signup')
    })

router
    .route('/login')
    
    .post((req, res, next) => {
        const { username, password } = req.body;
        //console.log('username:', username, 'password:', password)
        const userInfo = { username, password };
        console.log(userInfo)
        if (!username || !password) {
            return res.status(400).json({
                error: 'missing fields'
            })
        }
        AuthService.userExists(
            req.app.get('db'),
            username
        )
            .then(user => {
                console.log('USER', user)
                const userData = {
                    username: user.username,
                    email: user.email,
                    password: user.password,
                    lyrics: user.lyrics
                }
                bcrypt.compare(password, user.password, (err, result) => {
                    console.log('ran')
                    //console.log(err)
                    //console.log(res)
                    if (!result) {
                        return res.status(401).json({
                            error: 'incorrect password'
                        })
                    }
                    if ( result ) {
                        jwt.sign(userData, JWT_SECRET, {expiresIn: '30m'}, (err, token) => {
                            if (err){
                                res.statusMessage = err.message;
                                return res.status(400).end();
                            }
                            return res.status(200).json({ 
                                token,
                                lryics: userData.lyrics
                            });
                        })
                    }
                    /*return res.status( 401 ).json({
                        message: 'auth failed'
                    })*/
                })
            })
    })

    .get((req, res, next) => {
        let token = req.headers.sessiontoken;
        //console.log(req.headers)
        console.log(req.params)

        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if(err) {
                res.statusMessage = "Your session has expired, log in again";
                return res.status( 409 ).end();
            }

            return res.status( 200 ).json({
                username: decoded.username,
                lyrics: decoded.lyrics
            })
        })
    })
/*
router
    .route('/refresh')

    post('/refresh')
*/

router
    .route('/update')
    
    .post((req, res, next) => {
        const { username, lyrics } = req.body;
        console.log(req.body)
        console.log(req.body.username.length)
        if (!username || username.length < 1) {
            console.log('no user')
            return res.status(401).json({
                error: 'need to log in'
            })
        }
        AuthService.updateLyrics(
            req.app.get('db'),
            username,
            lyrics
        )
            .then(response => {
                console.log(response)
                return res.status(200).json({
                    message: 'updated lyrics'
                })
            })
        /*return res.status(200).json({
            message: 'updated lyrics'
        })*/
    })
module.exports = router;