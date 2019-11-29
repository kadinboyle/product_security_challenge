
const sqlite3 = require('sqlite3').verbose()
var db = new sqlite3.Database('data.db', sqlite3.OPEN_READWRIT);

const FAILED_LOGIN_LIMIT = 3;

module.exports = {
    getUserLoginDetails(username){
        const stmt = db.prepare('SELECT account_locked, password_hash FROM users WHERE username = ?');
        return new Promise(function(resolve, reject){
            stmt.get(username, (err, row) => {
                if(err){
                    console.err("Error occurred when retrieving auth details for user: ", username);
                    console.err(err);
                    return reject(null);
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
                    console.log("Error occurred while creating a new user", err);
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
        console.log("Incrementing failed logins for user", forUsername);
        const noFailedStmt = db.prepare("SELECT failed_login_counter FROM users WHERE username = ?");
        noFailedStmt.get(forUsername, (err, row) => {
            var stmt;
            if(row.failed_login_counter + 1 > FAILED_LOGIN_LIMIT) //dont bother storing if over limit including latest fail, going to reset anyway
                stmt = db.prepare("UPDATE users SET failed_login_counter = 0, account_locked = \"TRUE\" WHERE username = ?")
            else
                stmt = db.prepare("UPDATE users SET failed_login_counter = failed_login_counter + 1 WHERE username = ?");

            stmt.run(forUsername, err =>{
                if(err)
                    return console.error("Failed to increment failed login count for username:", forUsername);
            });
        });
    },

    resetLoginFailCount(forUsername){
        const stmt = db.prepare("UPDATE users SET failed_login_counter = 0 WHERE username = ?");
        stmt.run(forUsername, err => {
            if(err)
                console.error("Failed to reset login fail counter for username", forUsername);
        });
    }

}

