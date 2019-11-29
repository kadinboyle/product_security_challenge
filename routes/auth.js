var express = require('express');
var router = express.Router();
var path = require('path');
var csrf = require('csurf');
var csrfCheck = csrf();


var AuthHelpers = require("../user-auth-helper");
var userDAO = require('../user-dao');

const sqlite3 = require('sqlite3').verbose()
var db = new sqlite3.Database('data.db', sqlite3.OPEN_READWRIT);

function FailResponse(res, status, message){
    res.status(status);
    return res.json({status: "FAIL", message: message});
}

function SuccessResponse(res, status, message){
    res.status(status);
    return res.json({status: "SUCCESS", message: message});
}

router.post('/create-account', function(req, res, next) {
    if(!req.body.username || !req.body.password)
        return FailResponse(res, 404, "You mnust supply a username and password to register with");

    const user = req.body.username;
    const pword = req.body.password;
    //TODO: input validation / sanitization
    AuthHelpers.GeneratePasswordHash(pword, hash => {
        console.log("Hash built...", hash);
        userDAO.registerNewUser(user, hash).then(ok => {
            SuccessResponse(res, 200, "Successfully registered new user! You may now login");
        }).catch(err => {
            FailResponse(res, 400, "Failed to register new user");
        });
    });

});

router.post('/login', csrfCheck, function(req, res, next) {
    if(!req.body.username || !req.body.password)
        return FailResponse(res, 404, "You must supply user login details");

    const user = req.body.username;
    const pword = req.body.password;

    userDAO.getUser

    //TODO: input validation / sanitization
    
    userDAO.getUserLoginDetails(user).then(userDetails => {
        if(!userDetails || !userDetails.password_hash)
            return FailResponse(res, 400, "Incorrect login details");

        if(userDetails.account_locked == "TRUE")
            return FailResponse(res, 404, "Your account has been locked! Please contact an administrator.");

        AuthHelpers.ComparePasswordWithHash(pword, hash, isValid => {
            if(isValid){
                req.session.user = { username: user };
                return res.redirect('/protected');
            }
            
            const ip = req.connection.remoteAddress;
            console.log("Warning: Failed login attempt for username:", user, "by", ip);
            userDAO.incrementLoginFailCount(user);
            return FailResponse(res, 400, "Incorrect login details");
        });

    }).catch(err => {
        return FailResponse(res, 500, "An error has occurred processing login details");
    });

});

router.get('/logout', function(req, res) {
    if (req.cookies.session_id && req.session.user) 
        res.clearCookie('session_id');
    //req.session.destroy();
    res.redirect('/');
});


module.exports = router;