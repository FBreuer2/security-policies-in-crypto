const ECCLib = artifacts.require("ECC");

const ethereumJSUtil = require('ethereumjs-util');
const crypto         = require('crypto');

contract("ECRecover", async (accounts) => {
    let library;
  
    beforeEach(async () => {
  
      // Create contract.
      library = await ECCLib.deployed();
  
  
  });

  it("Signature check on curve SECP256K1 with SHA-3 and ethereum style prefixing", async() => {
    var secp256k1 = crypto.createECDH('secp256k1');
    secp256k1.generateKeys();



    // Create random message 
    let message = Buffer.from(Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 5));

    const hashedMsg = ethereumJSUtil.keccak256(message)
    const personalMsg = ethereumJSUtil.hashPersonalMessage(hashedMsg)
    const rsv = ethereumJSUtil.ecsign(personalMsg, secp256k1.getPrivateKey())

    signature = '0x' + rsv.r.toString('hex') + rsv.s.toString('hex') + rsv.v.toString(16);
    hashedMessage = '0x' + hashedMsg.toString('hex')
    let publicKey = '0x' + secp256k1.getPublicKey('hex');

    var result = await library.verifyECRecover(hashedMessage, publicKey, signature);
    assert.equal(result, true);
  });

});
  