const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const REGEX_UPPER_LOWER_NUMBER_SPECIAL = /(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&])[\S]+/
const xss = require('xss');
const { JWT_SECRET, JWT_EXPIRY } = require('../config')

const AuthService = {
    validatePassword(password) {
        if (password.length < 8) {
            return 'Password must be longer than 8 character'
        }
        if (password.length > 72) {
            return 'Password must be less than 72 characters'
        }
        if (password.startsWith(' ') || password.endsWith(' ')) {
            return 'Password must not start or end with empty spaces'
        }
        if (!REGEX_UPPER_LOWER_NUMBER_SPECIAL.test(password)) {
            return 'Password must contain 1 uper case, lower cass, number and space character'
        }
        return null
    },
    hasUserWithUserName(knex, username) {
        return knex.select('*')
            .from('users')
            .where({ username })
            .first()
            .then(user => !!user)
    },
    hasUserWithEmail(knex, email) {
        return knex.select('*')
            .from('users')
            .where({ email })
            .first()
            .then(user => !!user)
    },
    userExists(knex, username) {
        return knex.select('*')
            .from('users')
            .where({ username })
            .first()
            .then(user => user)
    },
    hashPassword(password) {
        return bcrypt.hash(password, 12)
    },
    serializeUser(user) {
        return {
            username: xss(user.username),
            email: xss(user.email),
            password: user.password
        }
    },
    createUser(knex, user) {
        return knex('users')
            .insert(user)
            .returning('*')
            .then(([user]) => user)
    },
    createJwt(subject, payload) {
        return jwt.sign(payload, JWT_SECRET, {
            subject,
            expiresIn: JWT_EXPIRY,
            algorithm: 'HS256',
        })
    },
    updateLyrics(knex, username, lyrics) {
        return knex('users')
            .where('username', username)
            .update({
                lyrics
            })
    }
    /*saveToken(token) {
        window.sessionStorage.setItem(TOKEN_KEY, token)
    },
    getAuthToken() {
        return window.sessionStorage.getItem(TOKEN_KEY)
    },
    clearAuthToken() {
        window.sessionStorage.removeItem(TOKEN_KEY)
    },
    hasAuthToken() {
        return !!AuthService.getAuthToken()
    },
    makeBasicAuthToken(userName, password) {
        return window.btoa(`${userName}:${password}`)
    },*/
}

module.exports = AuthService;