var express = require('express');
var router = express.Router();
var path = require('path');
var csrf = require('csurf');
var csrfCheck = csrf();

router.get('/', function(req, res, next) {
  if(req.session.user && req.cookies.session_id)
    return res.redirect('/protected');

  res.render('index', { title: 'Login Form', csrfToken: res.locals.csrfToken });
});

router.get('/create_account', function(req, res, next) {
  res.render('create_account', { title: 'Create Account', csrfToken: res.locals.csrfToken });
});

router.get('/reset_password', function(req, res, next) {
  res.render('reset_password', { title: 'Reset Password', csrfToken: res.locals.csrfToken });
});

router.get('/reset_password_thanks', function(req, res, next) {
  res.render('reset_password_thanks', { title: 'Reset Password' });
});

module.exports = router;
