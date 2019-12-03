var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
var passwordValidator = require('password-validator');
var badPasswords = require('./known-passwords');
var logger = require('./logging').logger;

const saltIterations = 10;
var passwordRules = new passwordValidator();
 
//normally i would prefer use of pass phrases but for simple demonstration for challenge have opted for simpler approach
passwordRules
.is().min(10)
.is().max(72)
//.has().lowercase()
//.has().uppercase() 
.is().not().oneOf(badPasswords); //this would not be efficient in production for large numbers of request / big lists

module.exports = {
    
    GeneratePasswordHash(password, cb){
        bcrypt.hash(password, saltIterations, function(err, hash) {
            if(err)
                console.err("An error occurred while generating a password hash");
            cb(hash);
        });
    },

    ComparePasswordWithHash(password, hash, cb){
        bcrypt.compare(password, hash, function(err, res) {
            if(err){
                console.err("An error occurred while comparing password with hash");
                return cb(false);
            }
                
            cb(res);//true or false
        });
    },

    //Use the users old password hash combined with a secret (env variable) so we don't need to maintain state on the server
    //and this token will only work until a new password is set
    //Tokens are valid for 30 mins (1800seconds)
    BuildPasswordResetToken(username, hash){
        logger.log(`Generating password reset token for user ${username}`);
        const resetToken = jwt.sign({ user: username }, `${hash}-${process.env.JWT_SECRET_APPEND}`, { expiresIn: 1800 });
        return resetToken;
    },

    ValidatePasswordResetToken(username, oldhash, token, req){
        const decodeSecret = `${oldhash}-${process.env.JWT_SECRET_APPEND}`;
        try {
            const payload = jwt.verify(token, decodeSecret, { maxAge: 1800 });
            if(!payload)
                return false;
            return (username === payload.user);
        }catch(err){ //can also indicate token expiry time is up
            const ip = req.connection.remoteAddress;
            logger.warn(`Warning: JWT Verification failed on password reset token received from ${ip} attempting to reset username ${username}`);
            return false;
        }
    },

    ValidatePassword(password){
        return passwordRules.validate(password);
    }

}