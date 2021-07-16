"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const axios = require('axios');
require('dotenv').config();
//import bodyParser = require('body-parser')
const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const ipRangeCheck = require("ip-range-check");
const AUTHORIZED_RESOURCE_SERVER_IP_RANGE_LIST = process.env.AUTHORIZED_RESOURCE_SERVER_IP_RANGE_LIST || '127.0.0.1';
const LISTEN_IP = process.env.LISTEN_IP || 'localhost';
const HOSTNAME = require('os').hostname();
const JWT_SIGN_EXPIRY = process.env.JWT_SIGN_EXPIRY || "30"; // In minutes
const SECRET = process.env.SECRET || "defaultSecret";
const LOG_LEVEL = process.env.LOG_LEVEL || "debug";
const SERVICE_PORT = process.env.SERVICE_PORT || 8080;
const WINSTON_HOST = process.env.WINSTON_HOST;
const WINSTON_PORT = process.env.WINSTON_PORT;
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
// Prevent default keys going into production
if (process.env.NODE_ENV == 'production') {
    if (SECRET == 'defaultSecret') {
        winston.info("You MUST change SECRET and PRIVATE_KEY before running in a production environment.");
        process.exit(1);
    }
}
if (process.env.NODE_ENV != 'production' ||
    process.env.CORS_ALLOW_ALL == 'true') {
    app.use(function (req, res, next) {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        next();
    });
}
////////////////////////////////////////////////////////
/*
 * Logger init
 */
////////////////////////////////////////////////////////
winston.level = LOG_LEVEL;
winston.remove(winston.transports.Console);
winston.add(winston.transports.Console, {
    'timestamp': true
});
if (process.env.WINSTON_PORT) {
    winston.add(winston.transports.Syslog, {
        host: WINSTON_HOST,
        port: WINSTON_PORT,
        protocol: 'udp4',
        localhost: HOSTNAME
    });
}
////////////////////////////////////////////////////////
/*
 * App Startup
 */
////////////////////////////////////////////////////////
const corsOptions = {
    origin: 'http://localhost:4200',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE, OPTIONS',
    preflightContinue: true,
    optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));
app.use(express.json());
var args = process.argv;
if (args.length == 3 && args[2] == 'server') {
    var server = app.listen(SERVICE_PORT, LISTEN_IP, function () {
        var host = server.address().address;
        var port = server.address().port;
        winston.info(`MyGov Captcha Service listening at http://${host}:${port}`);
        winston.info(`Log level is at: ${LOG_LEVEL}`);
    });
}
var verifyCaptcha = async function (payload) {
    winston.debug(`incoming payload: ` + JSON.stringify(payload));
    var gToken = payload.token;
    var nonce = payload.nonce;
    // Captcha by-pass for automated testing in dev/test environments
    if (process.env.BYPASS_ANSWER &&
        process.env.BYPASS_ANSWER.length > 0 &&
        process.env.BYPASS_ANSWER === gToken) {
        // Passed the captcha test
        winston.debug(`Captcha bypassed! Creating JWT.`);
        var token = jwt.sign({ data: { nonce: nonce } }, SECRET, { expiresIn: JWT_SIGN_EXPIRY + 'm' });
        return {
            valid: true,
            jwt: token
        };
    }
    axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${gToken}`, {}, {
        headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
        },
    })
        .then((res) => {
        let data = res.data;
        console.log("Google Response:", data);
    });
    return {
        valid: false
    };
    // Normal mode, verify token with google
    // let body: UnencryptedValidation = await decrypt(validation, PRIVATE_KEY)
    // winston.debug(`verifyCaptcha decrypted: ` + JSON.stringify(body))
    // if (body !== null) {
    //   // Check answer
    //   if (body.answer.toLowerCase() === answer.toLowerCase()) {
    //     if (body.nonce === nonce) {
    //       // Check expiry
    //       if (body.expiry > Date.now()) {
    //         // Passed the captcha test
    //         winston.debug(`Captcha verified! Creating JWT.`)
    //         var token = jwt.sign({
    //           data: {
    //             nonce: nonce
    //           }
    //         }, SECRET, {
    //             expiresIn: JWT_SIGN_EXPIRY + 'm'
    //           })
    //         return {
    //           valid: true,
    //           jwt: token
    //         }
    //       } else {
    //         // incorrect answer
    //         winston.debug(`Captcha expired: ` + body.expiry + "; now: " + Date.now())
    //         return {
    //           valid: false
    //         }
    //       }
    //     } else {
    //       // incorrect nonce
    //       winston.debug(`nonce incorrect, expected: ` + body.nonce + '; provided: ' + nonce)
    //       return {
    //         valid: false
    //       }
    //     }
    //   } else {
    //     // incorrect answer
    //     winston.debug(`Captcha answer incorrect, expected: ` + body.answer + '; provided: ' + answer)
    //     return {
    //       valid: false
    //     }
    //   }
    // } else {
    //   // Bad decyption
    //   winston.error(`Captcha decryption failed`)
    //   return {
    //     valid: false
    //   }
    // }
};
exports.verifyCaptcha = verifyCaptcha;
app.post('/verify/captcha', async function (req, res) {
    let ret = await verifyCaptcha(req.body);
    return res.send(ret);
});
var verifyJWT = async function (token, nonce) {
    winston.debug(`verifying: ${token} against ${nonce}`);
    try {
        var decoded = jwt.verify(token, SECRET);
        winston.debug(`decoded: ` + JSON.stringify(decoded));
        if (decoded.data && decoded.data.nonce === nonce) {
            winston.debug(`Captcha Valid`);
            return {
                valid: true
            };
        }
        else {
            winston.debug(`Captcha Invalid!`);
            return {
                valid: false
            };
        }
    }
    catch (e) {
        winston.error(`Token/ResourceID Verification Failed: ` + JSON.stringify(e));
        return {
            valid: false
        };
    }
};
exports.verifyJWT = verifyJWT;
app.post('/verify/jwt', async function (req, res) {
    let ipRangeArr = AUTHORIZED_RESOURCE_SERVER_IP_RANGE_LIST.split(',');
    let allowed = false;
    for (let ipRange of ipRangeArr) {
        if (ipRangeCheck(req.ip, ipRange.trim())) {
            allowed = true;
            break;
        }
    }
    if (!allowed) {
        winston.debug(`Unauthorized access to /verify/jwt from ip ${req.ip}.`);
        res.status(403).end();
        return;
    }
    let ret = await verifyJWT(req.body.token, req.body.nonce);
    res.send(ret);
});
// health and readiness check
app.get(/^\/(hello)?$/, function (req, res) {
    res.status(200).end();
});
app.get(/^\/(status)?$/, function (req, res) {
    res.send("OK");
});
