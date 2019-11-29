var express = require('express');
var router = express.Router();
var path = require('path');


/* GET home page. */
router.get('/', function(req, res, next) {
    res.render('display', { title: 'Login Form', username: req.session.user.username });

});

module.exports = router;