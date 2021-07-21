const axios = require('axios');
const jwt = require('jsonwebtoken');
const winston = require('./loggerSetup')();
const { SECRET, JWT_SIGN_EXPIRY, RECAPTCHA_SECRET_KEY, BYPASS_ANSWER } = require('./envConfig');

/**
 * Interfaces
 */

export interface VerifyJWTResponse {
  valid: boolean
}

interface VerifyCaptchaRequest {
  token: string,
  nonce: string,
}

export interface VerifyCaptchaValidResponse {
  valid: boolean,
  jwt: string
}

export interface VerifyCaptchaInvalidResponse {
  valid: boolean
}

/**
 * Helper Functions
 */

////////////////////////////////////////////////////////
/*
 * Verify ReCaptcha token
 */
////////////////////////////////////////////////////////

var verifyCaptcha = async function (payload: VerifyCaptchaRequest): Promise<VerifyCaptchaInvalidResponse | VerifyCaptchaValidResponse> {
  winston.debug(`incoming payload: ` + JSON.stringify(payload))
  var gToken = payload.token;
  var nonce = payload.nonce;

  // Captcha by-pass for automated testing in dev/test environments
  if (BYPASS_ANSWER &&
    BYPASS_ANSWER.length > 0 &&
    BYPASS_ANSWER === gToken) {

    // Passed the captcha test
    winston.debug(`Captcha bypassed! Creating JWT.`)

    var token = jwt.sign(
      { data: { nonce: nonce } },
      SECRET,
      { expiresIn: JWT_SIGN_EXPIRY + 'm' });

    return {
      valid: true,
      jwt: token
    }
  }

  axios.post(
    `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${gToken}`,
    {},
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
      },
    },
  )
    .then((res:any) => {
      let data = res.data;
      console.log("Google Response:", data);
    })

  return {
    valid: false
  }
}

////////////////////////////////////////////////////////
/*
 * Verify a JWT generated by us.
 */
////////////////////////////////////////////////////////

var verifyJWT = async function (token: string, nonce: string): Promise<VerifyJWTResponse> {
  winston.debug(`verifying: ${token} against ${nonce}`)
  try {
    var decoded = jwt.verify(token, SECRET)
    winston.debug(`decoded: ` + JSON.stringify(decoded))
    if (decoded.data && decoded.data.nonce === nonce) {
      winston.debug(`Captcha Valid`)
      return {
        valid: true
      }
    } else {
      winston.debug(`Captcha Invalid!`)
      return {
        valid: false
      }
    }
  } catch (e) {
    winston.error(`Token/ResourceID Verification Failed: ` + JSON.stringify(e))
    return {
      valid: false
    }
  }
}
module.exports = { verifyCaptcha, verifyJWT };