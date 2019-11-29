var bcrypt = require('bcrypt');

const saltIterations = 10;

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
    }
}
