const EllipticCurveLibrary = artifacts.require("EllipticCurve");

const bigNumber      = require('bignumber.js');
const crypto         = require('crypto');
const ecPem          = require('ec-pem');
const ethereumJSUtil = require('ethereumjs-util');


contract("EllipticCurve", async (accounts) => {
  let curve;
  let messageHash;
  let publicKey;
  let signature;

  beforeEach(async () => {

    // Create contract.
    curve = await EllipticCurveLibrary.deployed();

    // Create curve object for key and signature generation.
    var prime256v1 = crypto.createECDH('prime256v1');
    prime256v1.generateKeys();

    // Reformat keys.
    var pemFormattedKeyPair = ecPem(prime256v1, 'prime256v1');
    publicKey = [
      '0x' + prime256v1.getPublicKey('hex').slice(2, 66),
      '0x' + prime256v1.getPublicKey('hex').slice(-64)
    ];

    // Create random message and sha256-hash it.
    var message = Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 5);
    messageHash = ethereumJSUtil.bufferToHex(ethereumJSUtil.sha256(message));

    // Create signature.
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(message);
    var sigString = signer.sign(pemFormattedKeyPair.encodePrivateKey(), 'hex');

    // Reformat signature / extract coordinates.
    var xlength = 2 * ('0x' + sigString.slice(6, 8));
    var sigString = sigString.slice(8)
    signature = [
      '0x' + sigString.slice(0, xlength),
      '0x' + sigString.slice(xlength + 4)
    ];

});

  it("Simple signature check on SECPR1", async() => {
    var result = await curve.validateSignature(messageHash, signature, publicKey);
    assert.equal(result, true);
  });
});
