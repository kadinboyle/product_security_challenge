
const sqlite3 = require('sqlite3').verbose()
var db = new sqlite3.Database('data.db', sqlite3.OPEN_READWRIT);
var logger = require('./logging').logger;

const FAILED_LOGIN_LIMIT = 3;

module.exports = {
    getUserLoginDetails(username){
        const stmt = db.prepare('SELECT account_locked, password_hash FROM users WHERE username = ?');
        return new Promise(function(resolve, reject){
            stmt.get(username, (err, row) => {
                if(err){
                    logger.error(`Error occurred when retrieving auth details for user: ${username}`);
                    logger.error(err);
                    return reject(err);
                }

                if(!row)
                    return resolve(null);
                resolve(row);
            });
            stmt.finalize();
        });
    },

    registerNewUser(username, passwordHash){
        const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
        return new Promise(function(resolve, reject){
            stmt.run([username, passwordHash], err => {
                if(err){
                    if(err.errno != 19)
                        logger.log(`Error occurred while creating a new user ${err}`);
                    return reject(err);
                }
                else {
                    resolve();
                }
                   
            })
            stmt.finalize();
        });
    },

    updateUserPassword(username, newPasswordHash){
        const stmt = db.prepare('UPDATE users SET password_hash = ? WHERE username = ?')
        return new Promise(function(resolve, reject){
            stmt.run([newPasswordHash, username], err => {
                if(err){
                    logger.log(`Error occurred while updating password for ${username}: ${err}`);
                    return reject();
                }
                else {
                    resolve();
                }
            })
            stmt.finalize();
        });
    },

    incrementLoginFailCount(forUsername){
        const noFailedStmt = db.prepare("SELECT account_locked, failed_login_counter FROM users WHERE username = ?");
        noFailedStmt.get(forUsername, (err, row) => {
            var stmt;
            if(row.account_locked == "TRUE")
                return;

            logger.log(`Incrementing failed logins for user ${forUsername}`);
            if(row.failed_login_counter + 1 > FAILED_LOGIN_LIMIT) //dont bother storing if over limit including latest fail, going to reset anyway
                stmt = db.prepare("UPDATE users SET failed_login_counter = 0, account_locked = \"TRUE\" WHERE username = ?")
            else
                stmt = db.prepare("UPDATE users SET failed_login_counter = failed_login_counter + 1 WHERE username = ?");

            stmt.run(forUsername, err =>{
                if(err)
                    return logger.error(`Failed to increment failed login count for user: ${forUsername}`);
            });
        });
    },

    resetLoginFailCount(forUsername){
        const stmt = db.prepare("UPDATE users SET failed_login_counter = 0 WHERE username = ?");
        stmt.run(forUsername, err => {
            if(err)
                logger.error(`Failed to reset login fail counter for user: ${forUsername}`);
        });
    }

}

