
//Author: Kadin Boyle
//Desc:   Pretty rough and crude logger used for various playing around in node

var chalk = require('chalk');
var fs = require('fs');
var path = require('path');
var moment = require('moment');
var nodemailer = require('nodemailer');

class Logger {

    warnings = [];
    logFilenameOnly = "";
    logFile = "";
    doWriteToFile = true;
    doNotifyMailingList = false;

    constructor(options){
        var baseFilename = (moment().format('DD-MMM-YYYY')) + ".txt";

        if(options.filename != undefined && options.filename.length > 0)
            this.logFilenameOnly = options.filename + "-" + baseFilename;
        else
            this.logFilenameOnly = baseFilename;
    
        if(options.writeLogToFile != undefined)
            this.doWriteToFile = options.writeLogToFile;
        if(options.notifyMailingList != undefined)
            this.doNotifyMailingList = options.notifyMailingList;
        if(options.outputLogfilePath != undefined)
            this.logFile = options.outputLogfilePath;

        const logDir = path.join(__dirname, 'logs');
        if(!fs.existsSync(logDir))
            fs.mkdirSync(logDir);

        this.logFile = path.join(logDir, this.logFilenameOnly); //full path
        var self = this;
        
        fs.appendFile(this.logFile, "", function(err){
            if(!err){
                fs.chmodSync(String(self.logFile), "0660");
            }
        });
    }

    notifyAdminWarningEmail = function(warningMessage, timestamp){
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                    user: process.env.MAIL_AUTH_USER,
                    pass: process.env.MAIL_AUTH_PASS
                }
        });
    
        var mailBody = '<p>Zendesk Security Challenge System Warning!</p><br>';
        mailBody += `<p>Warning ${timestamp}: ${warningMessage}`;
    
        const mailOptions = {
            from: 'appdummy9989@email.com',
            to: process.env.ADMIN_EMAIL,
            subject: 'Zendesk Security Challenge - System Security Warning',
            html: mailBody
        };

        this.info("Sending warning email to admin");
        transporter.sendMail(mailOptions, function (err, info) {
        if(err)
            this.error(`Error occurred when sending warning email to admin: ${err}`)
        else if(info.accepted.length > 0)
            this.info("Email sent");
        });
    }

    getTimestamp = function(){
        return "[" + (moment().format('DD-MMM-YYYY HH:MM:SS')) + "]";
    }

    output = function(lineHeaderConsole, lineHeaderFile, message){
        console.log(lineHeaderConsole, message);
        var self = this;
        if(this.doWriteToFile){
            var lineToWrite = "\n" + lineHeaderFile + JSON.stringify(message);
            fs.appendFile(this.logFile, lineToWrite, function(err){
                if(err){
                    console.log("Failed to append line to file: " + err);
                }
            });
        }
    }

    outputFileonly = function(line){
        if(this.doWriteToFile){
            var lineToWrite = "\n" + chalk.blue.bold(this.getTimestamp() +  " [INFO]: ") + line;
            fs.appendFile(this.logFile, lineToWrite, function(err){
                if(err){
                    this.sysWarn("Failed to append message to log file");
                }
            });
        }
    }

    warn = function(message, notifyAdmin = false){
        const timestamp = this.getTimestamp();
        const lineHeader = timestamp +  " [WARN]: ";
        this.output(chalk.yellow.bold(lineHeader), lineHeader, message);
        if(notifyAdmin)
            this.notifyAdminWarningEmail(message, timestamp);
    }
    
    info = function(message){
        const lineHeader = this.getTimestamp() +  " [INFO]: ";
        this.output(chalk.blue.bold(lineHeader), lineHeader, message);
    }
    
    err = function(message){
        const lineHeader = this.getTimestamp() +  "  [ERR]: ";
        this.output(chalk.red.bold(lineHeader), lineHeader, message);
    }
    
    error = this.err;
    
    log = function(message){
        const lineHeader = this.getTimestamp() +  "  [LOG]: ";
        this.output(chalk.green.bold(lineHeader), lineHeader, message);
    }

    debug = function(message){
        if(process.env.NODE_ENV == "development"){
            const lineHeader = this.getTimestamp() + "[DEBUG]: "
            this.output(chalk.magenta.bold(lineHeader), lineHeader, message);
        }
    }
    
    setOutputLogFilepath = function(path){
        this.logFile = path;
    }

}

const logger = new Logger({
    writeLogToFile: false,
    filename: "zendesk-sec-challenge"
});

module.exports = {
    logger
}

