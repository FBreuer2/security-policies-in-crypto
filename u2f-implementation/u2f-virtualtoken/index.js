const KJUR = require('jsrsasign');
const crypto = require('crypto');
const ethereumJSUtil = require('ethereumjs-util');
const ecPem          = require('ec-pem');

/**
 * Internal Token Logic
 */

 var u2f = {};

 u2f.TokenTypes = {
    'SECP256R1WithSHA256': "secp256r_sha256",
    'SECP256K1WithEthereumStyleKeccak': "secp256k_keccak_prefixed"
 }

/**
 * Message types for messsages to/from the extension
 * @const
 * @type {{U2F_REGISTER_REQUEST: string, U2F_SIGN_REQUEST: string, U2F_REGISTER_RESPONSE: string, U2F_SIGN_RESPONSE: string}}
 */
u2f.MessageTypes = {
    'U2F_REGISTER_REQUEST': 'u2f_register_request',
    'U2F_SIGN_REQUEST': 'u2f_sign_request',
    'U2F_REGISTER_RESPONSE': 'u2f_register_response',
    'U2F_SIGN_RESPONSE': 'u2f_sign_response'
};

/**
 * Response status codes
 * @const
 * @type {{OK: number, OTHER_ERROR: number, BAD_REQUEST: number, CONFIGURATION_UNSUPPORTED: number, DEVICE_INELIGIBLE: number, TIMEOUT: number}}
 */
u2f.ErrorCodes = {
    "OK": 0,
    "OTHER_ERROR": 1,
    "BAD_REQUEST": 2,
    "CONFIGURATION_UNSUPPORTED": 3,
    "DEVICE_INELIGIBLE": 4,
    "TIMEOUT": 5
};

/**
 * The "future use" byte to add to a message
 * @type {string}
 * @const
 */
var FUTURE_USE_BYTE = '00';

/**
 * The "reserved" byte to add to a register request
 * @type {string}
 * @const
 */
var RESERVED_BYTE = '05';
/**
 * The byte indicating user presence
 * @type {string}
 * @const
 */
var USER_PRESENCE_BYTE = '01';

function hextob64(data) {
    // Pad out as required
    if (data.length % 2 != 0) {
        data = data + "0";
    }
    // Create standard b64 encoding
    var b64 =  new Buffer(data, 'hex').toString('base64');
    // Format to web safe b64
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64tohex(data) {
    return new Buffer(data, 'base64').toString('hex');
}

var exportedFunctions = {}
exportedFunctions.Type = u2f.TokenTypes;
exportedFunctions.U2FToken = class U2FToken {
    constructor(keys, algo) {
        if (algo != u2f.TokenTypes.SECP256K1WithEthereumStyleKeccak &&
            algo != u2f.TokenTypes.SECP256R1WithSHA256)
            return undefined;

        this.algo = algo;
    
        this.attestationKey = generateKeyPair(this.algo)
        this.attestationCertificate = generateAttestationCertificate(this.attestationKey, this.algo)
        this.keys = keys || [];

        return this;
    }

    // Save a key to the device
    SaveKey(applicationId, keyHandle, keyPair) {
    
        var key = {
            "generated" : (new Date()),
            "appId" : applicationId,
            "keyHandle" : keyHandle,
            "key": keyPair,
            "counter" : 0
        };

        this.keys.push(key);
    }

    GetKeyByHandle(keyHandle) {
        return this.keys.find(function(key) {
            return key.keyHandle == keyHandle;
        }) || null;
    }

    GetKeyByAppId(appId) {
        return this.keys.find(function(key) {
            return key.appId == appId;
        }) || null;
    }

    ExportKeys() {
        return this.keys;
    }

    ImportKeys(keys) {
        this.keys = keys;
    }

    /**
     * Determines whether a provided key handle belongs to a key that may be used by the app with the provided app id.
     * @param keyHandle
     * @param appId
     * @returns {boolean}
     */
    IsValidKeyHandleForAppId(keyHandle, appId) {
        
        var key = this.GetKeyByHandle(keyHandle);

        if (key === null) {
            return false;
        }

        if (key.appId === appId) {
            return true;
        } else {
            return false;
        }
    };

    // Handle a registration request
    HandleRegisterRequest(request) {

        //Check if appId is unique
        var existingKey = this.GetKeyByAppId(request.appId);
        if(existingKey != null) {
            return Promise.reject("Application key already exists");
        }

        var keyPair = generateKeyPair(this.algo);

        var clientData = getClientDataStringFromRequest(request);

        // we can always hash this with SHA-256 since it does not matter to the signature
        var clientDataHash = hashHex(clientData.toString('hex'), u2f.TokenTypes.SECP256R1WithSHA256);
        var applicationIdHash = hashHex(request.appId.toString('hex'), u2f.TokenTypes.SECP256R1WithSHA256);


        var keyHandle = generateKeyHandle();
        var keyHandleLength = getKeyHandleLengthString(keyHandle);

        var registrationBaseString = getRegistrationSignatureBaseString(applicationIdHash, clientDataHash, keyHandle, keyPair.getPublicKey('hex'));

        var signature = signHex(this.attestationKey, this.algo, registrationBaseString);

        var response = RESERVED_BYTE + keyPair.getPublicKey('hex') + keyHandleLength + keyHandle + this.attestationCertificate.toString('hex') + signature;

        this.SaveKey(request.appId, keyHandle, keyPair);

        /*
         * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll. 175-182
         */
        return Promise.resolve({
            // websafe-base64(raw registration response message)
            registrationData: hextob64(response),

            // websafe-base64(UTF8(stringified(client data)))
            clientData: new Buffer(clientData).toString('base64'),

            // Unencoded key handle for convenience
            keyHandle: keyHandle
        });
    };

    register(appId, registerRequests, registeredKeys, registerCallback, timeout) {
        HandleRegisterRequest({
            appId: appId, 
            registerRequests: registerRequests,
            registeredKeys: registeredKeys
        }).then(function(res) {
            registerCallback(res)
        }, function(err) {
            registerCallback({errorCode: err})
        });
    };

    /**
     * Handles a sign request
     * @param request
     * @param sender
     * @param sendResponse
     */
    HandleSignRequest(request) {
        
        var usedKey = request.registeredKeys.find(function(item) {
            return this.IsValidKeyHandleForAppId(b64tohex(item.keyHandle), request.appId);
        }.bind(this)) || null;

        if(usedKey == null) {
            return Promise.reject({
                errorCode: u2f.ErrorCodes.DEVICE_INELIGIBLE,
                errorMessage: "Not a valid device for this key handle/app id combination"
            });
        }

        var key = this.GetKeyByHandle(b64tohex(usedKey.keyHandle));

        if (key.appId != request.appId) {
            return Promise.reject({
                errorCode: u2f.ErrorCodes.DEVICE_INELIGIBLE,
                errorMessage: "keyHandle and appId mismatch"
            });
        } 

        // Always use Sha256 since it doesn't matter here
        var clientData = getClientDataStringFromRequest(request);
        var clientDataHash = hashHex(clientData.toString('hex'), u2f.TokenTypes.SECP256R1WithSHA256);
        var applicationId = getApplicationIdFromRequest(request);
        var applicationIdHash = hashHex(applicationId.toString('hex'), u2f.TokenTypes.SECP256R1WithSHA256);

        //var sessionID = getSessionIdFromRequest(request);
        var challenge = getChallengeFromRequest(request);
        var counterHex = counterPadding(key.counter);

        var signatureBase = getSignSignatureBaseString(applicationIdHash, counterHex, clientDataHash);
        var signature = signHex(key.key, this.algo, signatureBase);
        
        var signatureData = hextob64(USER_PRESENCE_BYTE + counterHex + signature);
        
        if (key.counter >= 65535) {
            key.counter = 0;
        } else {
            key.counter ++;
        }

        /*
         * fido-u2f-javascript-api-v1.0-rd-20140209.pdf ll.254 - 265
         */
        return Promise.resolve({
            // websafe-base64(client data)
            clientData : new Buffer(clientData).toString('base64'),

            // websafe-base64(raw response from U2F device)
            signatureData : signatureData,

            // challenge originally passed to handleSignRequest
            challenge : challenge,

            // session id originally passed to handleSignRequest
            //sessionId : sessionID,

            // application id originally passed to handleSignRequest
            appId : applicationId,

            // Unencoded key handle for convenience
            keyHandle: hextob64(key.keyHandle)
        });
    };

    /**
     * Handle a registration request
     * of the Google's Ref Code format
     * @param request
     */
    HandleRefCodeRegisterRequest(request) {
        request.type = u2f.MessageTypes.U2F_REGISTER_REQUEST;
        request.registerRequests = [{
            challenge: request.challenge,
        }];

        return this.HandleRegisterRequest(request);
    }

    /**
     * Handles a sign request object
     * of the Google's Ref Code format
     * @param request
     */
    HandleRefCodeSignRequest(request) {
        request.type = u2f.MessageTypes.U2F_SIGN_REQUEST;
        request.registeredKeys = [{
            keyHandle: request.keyHandle,
        }];

        return this.HandleSignRequest(request);
    }
};


/**
 * Padds an integer for counter byte use
 * @param num
 * @returns {string}
 */
var counterPadding = function (num) {
    return ("00000000" + num.toString(16)).substr(-8);
}


var signHex = function (key, algo, message) {
    if (algo == u2f.TokenTypes.SECP256K1WithEthereumStyleKeccak) {
        hashedMsg = ethereumJSUtil.keccak256(Buffer.from(message, 'hex'));
        personalMsg = ethereumJSUtil.hashPersonalMessage(hashedMsg)
        rsv = ethereumJSUtil.ecsign(personalMsg, Buffer.from(key.getPrivateKey('hex'), 'hex'));
        return Buffer.from(rsv.r.toString('hex') + rsv.s.toString('hex') + rsv.v.toString(16), 'hex').toString('hex');
    } else if (algo == u2f.TokenTypes.SECP256R1WithSHA256) {
        var signer = crypto.createSign('RSA-SHA256');
        signer.update(message, 'hex');
        return signer.sign(ecPem(key, 'prime256v1').encodePrivateKey(), 'hex');
    }
    
    return undefined;
};


var verifyHex = function(message, key, signature, algo) {
    if (algo == u2f.TokenTypes.SECP256K1WithEthereumStyleKeccak) {
        // A signature is built like this:
        // r (32 bytes) | s (32 Bytes) | v (1 byte)
        
        hashedMsg = ethereumJSUtil.keccak256(Buffer.from(message, 'hex'));
        personalMsg = ethereumJSUtil.hashPersonalMessage(hashedMsg)

        data = Buffer.from(signature, 'hex');

        let r = data.slice(0, 32);
        let s = data.slice(32, 64);
        let v = data.readUInt8(64);

        let recoveredPublicKey = ethereumJSUtil.ecrecover(personalMsg, v, r, s).toString('hex');
        let pubKey = key.getPublicKey('hex').slice(2);

        return (pubKey == recoveredPublicKey);
    } else if (algo == u2f.TokenTypes.SECP256R1WithSHA256) {
        var verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(message, 'hex');
        return verifier.verify(ecPem(key, 'prime256v1').encodePublicKey(), signature, 'hex');
    }
    
    return undefined;
}

/**
 * Gets a signature base String for registration
 *
 * @param applicationParameter
 * @param challengeParameter
 * @param keyHandle
 * @param userPublicKey
 * @returns {string} The signature base string
 */
var getRegistrationSignatureBaseString = function (applicationParameter, challengeParameter, keyHandle, userPublicKey) {
    
    return FUTURE_USE_BYTE + applicationParameter + challengeParameter + keyHandle + userPublicKey;
};

/**
 * Gets a signature base String for signin
 *
 * @param applicationParameter
 * @param challengeParameter
 * @param keyHandle
 * @param userPublicKey
 * @returns {string} The signature base string
 */
var getSignSignatureBaseString = function (applicationParameter, counter, challenge) {
    
    return applicationParameter + USER_PRESENCE_BYTE + counter + challenge;
};

/**
 * Converts a decimal number < 256 to a heaxadecimal byte representation.
 * @param {Integer} dec Decimal number < 255
 * @returns {string}
 */
var decimalNumberToHexByte = function (dec) {
    
    if (dec > 255) {
        throw new Error("Number exceeds a byte.");
    }
    return (dec + 0x10000).toString(16).substr(-2);
};


var hashHex = function(message, algorithm)  {
    if (algorithm == u2f.TokenTypes.SECP256R1WithSHA256) {
        return crypto.createHash('sha256').update(message, 'hex').digest().toString('hex');
    } else if (algorithm == u2f.TokenTypes.SECP256K1WithEthereumStyleKeccak) {
        return ethereumJSUtil.keccak256(message).toString('hex');
    }

    return undefined;
}

var generateKeyHandle = function () {
    return crypto.randomBytes(16).toString('hex');
};

var getClientDataStringFromRequest = function (request) {
    
    switch (request.type) {
        case u2f.MessageTypes.U2F_REGISTER_REQUEST:
            return Buffer.from(JSON.stringify({challenge: request.registerRequests[0].challenge}));
            break;
        case u2f.MessageTypes.U2F_SIGN_REQUEST:
            return Buffer.from(JSON.stringify({challenge: request.challenge}));
            break;
        default:
            throw new Error("Invalid Request Type");
        break;
    }
};

var getChallengeFromRequest = function (request) {
    return getClientDataStringFromRequest(request);
};

var getApplicationIdFromRequest = function (request) {
    
    switch (request.type) {
        case u2f.MessageTypes.U2F_REGISTER_REQUEST:
            return request.registerRequests[0].appId;
            break;
        case u2f.MessageTypes.U2F_SIGN_REQUEST:
            return request.appId;
            break;
        default:
            throw new Error("Invalid Request Type");
        break;
    }
};


var generateKeyPair = function(tokenType) {
    if (tokenType == u2f.TokenTypes.SECP256R1WithSHA256) {
        var secpr1 = crypto.createECDH('prime256v1');
        secpr1.generateKeys();
        return secpr1;
    } else if (tokenType == u2f.TokenTypes.SECP256K1WithEthereumStyleKeccak) {
        var secp256k1 = crypto.createECDH('secp256k1');
        secp256k1.generateKeys();
        return secp256k1;
    }  
}



var generateAttestationCertificate = function(key, algo) {
    var ecdsa;

    if (algo == u2f.TokenTypes.SECP256K1WithEthereumStyleKeccak) {
        ecdsa = new KJUR.crypto.ECDSA({
        "curve": "secp256k1"
        });
    } else if (algo == u2f.TokenTypes.SECP256R1WithSHA256) {
        ecdsa = new KJUR.crypto.ECDSA({
            "curve": "secp256r1"
        });
    }

   ecdsa.setPrivateKeyHex(key.getPrivateKey('hex'));
   ecdsa.setPublicKeyHex(key.getPublicKey('hex'));

   var tbsc = new KJUR.asn1.x509.TBSCertificate();
   tbsc.setSerialNumberByParam({
       "int": 1
   });

   if (algo == u2f.TokenTypes.SECP256K1WithEthereumStyleKeccak) {

    // unfortunately there isn't a "right" algorithm for our use case
        tbsc.setSignatureAlgByParam({
            "name": "SHA256withECDSA"
        });
    } else if (algo == u2f.TokenTypes.SECP256R1WithSHA256) {
        tbsc.setSignatureAlgByParam({
            "name": "SHA256withECDSA"
        });
    }   

   tbsc.setIssuerByParam({
       "str": "/C=DE/O=Untrustworthy CA Organisation/ST=Berlin/CN=Untrustworthy CA"
   });
   tbsc.setNotBeforeByParam({
       "str": "20140924120000Z"
   });
   tbsc.setNotAfterByParam({
       "str": "21140924120000Z"
   });
   tbsc.setSubjectByParam({
       "str": "/C=DE/O=virtual-u2f-manufacturer/ST=Berlin/CN=virtual-u2f-v0.0.1"
   });

   tbsc.setSubjectPublicKeyByGetKey(ecdsa);

   var cert = new KJUR.asn1.x509.Certificate({
       "tbscertobj": tbsc,
       "prvkeyobj" : ecdsa
   });

   cert.sign();

   // PEM -> DER means take away the first and last line (-----BEGIN CERTIFICATE-----) and (-----END CERTIFICATE-----)
   // trim whitespaces and then decode the base64
   let pemString = cert.getPEMString()

   // remove certificate string at start and end
   pemString = pemString.replace("-----BEGIN CERTIFICATE-----",'')
   pemString = pemString.replace("-----END CERTIFICATE-----",'')

   // remove whitespaces
   pemString = pemString.replace(/\s/g,'')

   attestationBuf = Buffer.from(pemString, 'base64');

   return attestationBuf.toString('hex')
}

var getKeyHandleLengthString = function (keyHandle) {
    
    return decimalNumberToHexByte(keyHandle.length / 2);
};

module.exports = exportedFunctions;