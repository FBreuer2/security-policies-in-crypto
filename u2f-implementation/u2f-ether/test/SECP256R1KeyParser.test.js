const ECCLib = artifacts.require("ECC");

const bigNumber      = require('bignumber.js');
const crypto         = require('crypto');
const ecPem          = require('ec-pem');
const ethereumJSUtil = require('ethereumjs-util');

contract("EllipticCurve", async (accounts) => {
  let library;

  beforeEach(async () => {

    // Create contract.
    library = await ECCLib.deployed();


});

  it("Signature check on curve SECP256R1 with SHA-2", async() => {
    // Create curve object for key and signature generation.
    var prime256v1 = crypto.createECDH('prime256v1');
    prime256v1.generateKeys();


    // Reformat keys.
    var pemFormattedKeyPair = ecPem(prime256v1, 'prime256v1');
    publicKey = '0x' + prime256v1.getPublicKey('hex');

    // Create random message and sha256-hash it.
    var message = Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 5);
    messageHash = ethereumJSUtil.bufferToHex(ethereumJSUtil.sha256(message));

    // Create signature.
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(message);
    var sigString = signer.sign(pemFormattedKeyPair.encodePrivateKey(), 'hex');
    var unchangedSig = '0x' + sigString;

    var result = await library.verifySECP256R1(messageHash, publicKey, unchangedSig);
    assert.equal(result, true);
  });

  it("Known good #0 (no padding)", async() => {
    var messageHash = '0xbf89ab4fd0a1d9a8a48f4cfec651ea8e37aaef5e881b891aba908f0e7b4f7202';
    var publicKey = '0x041b32e1c08e07f59a3c85881b0f4d162bd5a66ef78a3d954cb570057cc13e91b8b495be95a0743afd076fed56b3081974917edb61816bc0367946fe7e3a7e6363';
    var unchangedSig = '0x3044022071850da38bd5931b054e6d6cddd85771a431f537734716cef31eda5ff2b5e2290220642b8e2e45e90aeeaa74287b74cb17ef6976d3a29d6656041b47fa7ba0b2d24e';
    var result = await library.verifySECP256R1(messageHash, publicKey, unchangedSig);
    assert.equal(result, true);
  });

  it("Known good #1 (first point padded)", async() => {
    var messageHash = '0x5c7e51e4b1e40cfe7151e6dd5b502c72eb824115e4dbbe3bee532f16c48cd80f';
    var publicKey = '0x04a3a905a912b5c6dac87c38a210d74987973026cfcca0080c1b4fb67336511387e20c365a0d1ffcf6eb200506fdd75d12ac5117b239fc266fd1e849ecf5ea93f8';
    var unchangedSig = '0x3045022100e131c013227e2c09e9c992ced6da3694af5341561e94329db892985d06f5323202206317703cf5842f73cebd04b241302eddf434af0dc9ca41329929e1e9d366bab9';
    var result = await library.verifySECP256R1(messageHash, publicKey, unchangedSig);
    assert.equal(result, true);
  });

  it("Known good #2 (second point padded)", async() => {
    var messageHash = '0xc8f52d7493b46ddded21885e436a5c3166001b1e1a29d5a373517ea66f94169e';
    var publicKey = '0x04390d0f87ecff8a903a2fc703993bc91f0360c945fd2e391512cbf587a4c51eaffe990e6292df733ab158b1d0ff10c8cabc7423e1ff79127bcdedd8ebaffbcb48';
    var unchangedSig = '0x304502204d98073d9c82630583c4f1c3ab250aa21308bc36ce17e4f40510014bdc2f5b90022100e1e152b0c022cdfd2d2f5754cf3d0cc69cf2cb2f00ee6f175a3e652326cc23af';
    var result = await library.verifySECP256R1(messageHash, publicKey, unchangedSig);
    assert.equal(result, true);
  });

  it("Known good #3 (both points padded)", async() => {
    var messageHash = '0xb310e745ae5e9829f395508c44c5f0ccb625c318c7841e73ecc9e2232d712675';
    var publicKey = '0x0432188b3632ac78f7b9069feffff99e429a5954cef030e47bf61f7aec0467be991f5e986b971675cafdcd58e6d00728d98bdf0448c849591d47b61e06b981c481';
    var unchangedSig = '0x30460221009c7f65350c9a03ce8489ca4cc8b4600956fe1414656a4c296418eff6d830a2a3022100f69e5670eec601b9ad99657593a10732b718412f9dd79dee9fe3e1739d3f9ae4';
    var result = await library.verifySECP256R1(messageHash, publicKey, unchangedSig);
    assert.equal(result, true);
  });

});
