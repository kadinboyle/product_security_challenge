var express = require('express');
var router = express.Router();
var path = require('path');
var csrf = require('csurf');
var csrfCheck = csrf();
var nodemailer = require('nodemailer');
var validator = require('validator');

var AuthHelpers = require("../user-auth-helper");
var userDAO = require('../user-dao');
var logger = require('../logging').logger;

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
    var user = req.body.username;
    const pword = req.body.password;

    if(!user || !pword)
        return res.render('create_account_landing', { title: "Account Creation Failed", message: "You must supply a username and password!" });

    user = user.trim();
    if(!validator.isEmail(user) || !AuthHelpers.ValidatePassword(pword))
        return res.render('create_account_landing', { title: "Account Creation Failed", message: "You must supply a username (email format) and password between 10 - 72 characters, to register with. Your password must not be a common password." });

    //would do further sanitization here for untrusted user input

    logger.log(`Attempting to create new account with request from ${req.connection.remoteAddress}`);
    AuthHelpers.GeneratePasswordHash(pword, hash => {
        userDAO.registerNewUser(user, hash).then(ok => {
            logger.log("Account creation successful");
            return res.render('create_account_landing', { title: "Account Creation Successful", message: "Successfully registered new user! You may now login" });
        }).catch(err => {
            if(err.errno == 19) //username already exists in DB
                logger.warn(`Attempt to create account with username that is already registered by ${req.connection.remoteAddress}`);
            return res.render('create_account_landing', { title: "Account Creation Failed", message: "Failed to register new account" });
        });
    });
});

//generate password reset token for user
router.post('/reset-password-request', function(req, res, next) {
    if(!req.body.username || !validator.isEmail(req.body.username ))
        return FailResponse(res, 404, "You must supply a username");

    const user = req.body.username.trim();
    
    //sanitization if needed

    userDAO.getUserLoginDetails(user).then(userDetails => {
        if(!userDetails || !userDetails.password_hash)
            return FailResponse(res, 400, "Cannot reset your password at this time");

        if(userDetails.account_locked == "TRUE"){
            logger.warn(`Attempt to initiate password reset for locked account with username ${user} by ${req.connection.remoteAddress}`, true);
            return FailResponse(res, 404, "Your account has been locked! Please contact an administrator.");
        }
            
        const token = AuthHelpers.BuildPasswordResetToken(user, userDetails.password_hash);
        const link = `http://localhost:3000/auth/reset-password-update?username=${user}&token=${encodeURIComponent(token)}`;

        SendPasswordResetEmail(user, link);
        res.redirect('/reset_password_thanks');
    }).catch(err => {
        logger.error(err);
        return FailResponse(res, 400, "Something has gone wrong. Please try again later");
    });
});

router.get('/reset-password-update', function(req, res, next) {
    const username = req.query.username;
    const token = req.query.token;

    if(!username || !validator.isEmail(username) || !token || !validator.isJWT(token))
        return FailResponse(res, 400, "You must supply a username and reset token");

    res.render('reset_password_update', { title: 'Update Password', csrfToken: res.locals.csrfToken, username: username, token: token });
});

//actually updates the users password if they supply a valid reset token
router.post('/reset-password-update', function(req, res, next) {
    const username = req.body.username;
    const suppliedToken = req.body.resetToken;
    const newPassword = req.body.password;

    if(!username || !validator.isEmail(username) 
                || !suppliedToken 
                || !validator.isJWT(suppliedToken)
                || !newPassword 
                || !AuthHelpers.ValidatePassword(pword))
        return FailResponse(res, 400, "You must supply a valid username, reset token and password to update");

    userDAO.getUserLoginDetails(user).then(userDetails => {
        if(!userDetails || !userDetails.password_hash)
            return FailResponse(res, 400, "Cannot reset your password at this time");

        if(userDetails.account_locked == "TRUE")
            return FailResponse(res, 404, "Your account has been locked! Please contact an administrator.");

        const isValid = AuthHelpers.ValidatePasswordResetToken(user, userDetails.password_hash, suppliedToken, req);
        if(isValid){
            AuthHelpers.GeneratePasswordHash(newPassword, newHash => {
                userDAO.updateUserPassword(user, newHash).then(ok => {
                    logger.log(`Successfully reset password for user ${user}`);
                    return res.render('reset_password_update_landing', { title: 'Reset Password Success', message: "Your password has been successfully reset" });
                }).catch(err => {
                    return res.render('reset_password_update_landing', { title: 'Reset Password Failure', message: "Something has gone wrong and your password has not been reset. Please try again." });
                });
            });
        } else {
            return res.render('reset_password_update_landing', { title: 'Reset Password Failure', message: "Something has gone wrong and your password has not been reset. Please try again." });
        }
    }).catch(err => {
        return res.render('reset_password_update_landing', { title: 'Reset Password Failure', message: "Something has gone wrong and your password has not been reset. Please try again." });
    });
});

router.post('/login', csrfCheck, function(req, res, next) {
    if(!req.body.username || !req.body.password)
        return FailResponse(res, 404, "You must supply user login details");

    const user = req.body.username;
    const pword = req.body.password;
    
    userDAO.getUserLoginDetails(user).then(userDetails => {
        if(!userDetails || !userDetails.password_hash)
            return res.render('login_fail', {title: "Login Fail", message: "Incorrect login details"});

        if(userDetails.account_locked == "TRUE")
            return res.render('login_fail', {title: "Login Fail - Account Locked", message: "Your account has been locked! Please contact an administrator."});

        AuthHelpers.ComparePasswordWithHash(pword, userDetails.password_hash, isValid => {
            if(isValid){
                req.session.user = { username: user };
                return res.redirect('/protected');
            }
            
            const ip = req.connection.remoteAddress;
            logger.warn(`Failed login attempt for username ${user} by ${ip}`);
            userDAO.incrementLoginFailCount(user);
            return res.render('login_fail', {title: "Login Fail", message: "Incorrect login details"});
        });

    }).catch(err => {
        logger.error(err);
        return FailResponse(res, 500, "An error has occurred processing login details");
    });

});

router.get('/logout', function(req, res) {
    if (req.cookies.session_id && req.session.user) 
        res.clearCookie('session_id');
    //req.session.destroy();
    res.redirect('/');
});

function SendPasswordResetEmail(recipient, link){
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
                user: process.env.MAIL_AUTH_USER,
                pass: process.env.MAIL_AUTH_PASS
            }
    });

    var mailBody = '<p>A password reset request has been request for your Zendesk Security Challenge account.</p>'
    mailBody += 'Please follow the link below to reset your password. Note: this link is only valid for 30 minutes.</p><br><br>';
    mailBody += `<a href="${link}">Reset Password</a>`;

    const mailOptions = {
        from: 'appdummy9989@email.com',
        to: recipient,
        subject: 'Zendesk Security Challenge - Password Reset Request',
        html: mailBody
    };

    logger.log(`Sending password reset email to ${recipient}`);
    transporter.sendMail(mailOptions, function (err, info) {
    if(err)
        logger.error(`Error occurred when sending password reset email: ${err}`)
    else if(info.accepted.length > 0)
        logger.log("Email sent");
    });
}

module.exports = router;