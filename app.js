var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var helmet = require('helmet');
var session = require('express-session');
var csrf = require('csurf');
var csrfCheck = csrf();
var rateLimit = require("express-rate-limit");

var indexRouter = require('./routes/index');
var auth = require('./routes/auth');
var protected = require('./routes/protected');

function isAuthenticated(req, res, next){
    if(req.session.user && req.cookies.session_id)
        next();
    else
        res.redirect('/');
}

var sessionOptions = {
    secret: 'MedZ9DdVsg4zMVxY3bQZeriKB4jwtqyI',
    name: 'session_id',
    saveUninitialized: false,
    resave: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        //secure: true
    }
};

//Allow 500 requests every 5 minutes from a given IP
const generalLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    onLimitReached: function(req, res, options){
        const ip = req.connection.remoteAddress;
        console.log(`Warning: ${ip} has exceeded general request limit.`);
    },
    max: 500,
    message: "Too many requests. Please try again later"
});

//auth bcrypt functions can be resource intensive, limit these more than standard api requests
const authLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    onLimitReached: function(req, res, options){
        const ip = req.connection.remoteAddress;
        console.log(`Warning: ${ip} has exceeded authentication API request limit.`);
    },
    max: 5,
    message: "Too many requests to authentication API. Please try again later."
});

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(helmet({noSniff: false}));
app.use(cookieParser());
app.use(session(sessionOptions));

app.use('/protected', isAuthenticated, protected);
app.use('/assets', express.static(path.join(__dirname, 'public/assets')));

app.use(csrfCheck, (req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
  });

app.use('/', generalLimiter, indexRouter);
app.use('/auth', authLimiter, auth);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    next(createError(404));
  });
  
  // error handler
  app.use(function(err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
  
    // render the error page
    res.status(err.status || 500);
    res.render('error');
  });

module.exports = app;

