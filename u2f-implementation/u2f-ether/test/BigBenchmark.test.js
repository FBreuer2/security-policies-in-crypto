const BankAccounts = artifacts.require('BankAccounts');
var fs = require('fs');

const virtualu2fToken = require('../../u2ftoken');
var URLSafeBase64 = require('urlsafe-base64');
const crypto = require('crypto');
const parser = require('tder')


const STRATEGY = {
    VERIFY_DIRECTLY: "DIRECT",
    VERIFY_END: "END"
}

contract("BigBenchmark", async (accounts) => {
    let contract;
  
    beforeEach(async () => {
      // Create contract
      contract = await BankAccounts.deployed();
  
  });

 /*
 * Format:
 * Type | ID | Transactions | Strategy | RegistrationCost | AverageCreate | Average Verify
 * */
  function aggregatedToCSV(results, name) {

    var csv = fs.createWriteStream(name + '.csv')

      var csvString = 'Type, ID (in registration order), TransactionAmount, Strategy, RegistrationCost, AverageCreationCost, AverageVerificationCost\r\n'
      csv.write(csvString)
      var id = 1;
      for (var i = 0; i<results.secp256k.length; i++) {

        var line = 'SECP256K, ' + id + ', '  + results.secp256k[i].rawGen.length + ', ' + results.secp256k[i].strategy + ', ' +
                      results.secp256k[i].registration + ',' + results.secp256k[i].transactionGeneration + ', ' + results.secp256k[i].transactionVerification + '\r\n'
        id++;
        csv.write(line)
      }

      for (var i = 0; i<results.secp256r.length; i++) {

        var line = 'SECP256R, ' + id + ', '  + results.secp256r[i].rawGen.length + ', ' + results.secp256r[i].strategy + ', ' +
                      results.secp256r[i].registration + ',' + results.secp256r[i].transactionGeneration + ', ' + results.secp256r[i].transactionVerification + '\r\n'
        id++;
        csv.write(line)
      }

      csv.end()

  }

  function aggregatedSpecificArray(results, name) {
    var csv = fs.createWriteStream(name + '.csv')
    var csvString = 'ID,  Cost\r\n'
    csv.write(csvString)
    var id = 1;
    for (var i = 0; i<results.length; i++) {

      var line = id + ',' +  results[i] + '\r\n'
      id++;
      csv.write(line)
    }

    csv.end()

  }

  it("CSV aggregate", async(done) => {
      var SEPC256KConfig = {
          TokenAmount: 1,
          Transactions: 100,
          strategy: STRATEGY.VERIFY_DIRECTLY
      }

      var SEPC256RConfig = {
        TokenAmount: 10,
        Transactions: 100,
        strategy: STRATEGY.VERIFY_END
    }

    var testResults = await simulateUsers(accounts, SEPC256KConfig, null)

    console.log('Average SECP256R1')
    console.log('Registration: ' + testResults.aggregated.secp256r.reg)
    console.log('Creation: ' + testResults.aggregated.secp256r.create)
    console.log('Verification: ' + testResults.aggregated.secp256r.verify)

    console.log('Average SECP256K1')
    console.log('Registration: ' + testResults.aggregated.secp256k.reg)
    console.log('Creation: ' + testResults.aggregated.secp256k.create)
    console.log('Verification: ' + testResults.aggregated.secp256k.verify)

    //aggregatedToCSV(testResults, 'results')
    aggregatedSpecificArray(testResults.secp256k[0].rawGen, 'generation')
    aggregatedSpecificArray(testResults.secp256k[0].rawVer, 'verification')
}).timeout(0);



  async function simulateUsers(accountsToUse, SECP256KConfig, SECP256RConfig) {
    var accountIndex = 0;

    var testResults = {
        secp256k: [],
        secp256r: [],
        aggregated: {
            secp256k: {
                reg: 0,
                create: 0,
                verify: 0
            },

            secp256r:  {
                reg: 0,
                create: 0,
                verify: 0
            },
        }
    }

    if (SECP256KConfig != null) {
        for (var i = 0; i<SECP256KConfig.TokenAmount; i++) {
            var interim = await simulateOneToken(accountsToUse[accountIndex], new virtualu2fToken.U2FToken([], virtualu2fToken.Type.SECP256K1WithEthereumStyleKeccak), SECP256KConfig.Transactions, SECP256KConfig.strategy)
            testResults.secp256k.push(interim)
            testResults.aggregated.secp256k.reg += interim.registration
            testResults.aggregated.secp256k.create += interim.transactionGeneration
            testResults.aggregated.secp256k.verify += interim.transactionVerification
            accountIndex++;
        }

        testResults.aggregated.secp256k.reg /= SECP256KConfig.TokenAmount
        testResults.aggregated.secp256k.create /= SECP256KConfig.TokenAmount
        testResults.aggregated.secp256k.verify /= SECP256KConfig.TokenAmount

    }

    if (SECP256RConfig != null) {
        for (var i = 0; i<SECP256RConfig.TokenAmount; i++) {
            var interim = await simulateOneToken(accountsToUse[accountIndex], new virtualu2fToken.U2FToken([], virtualu2fToken.Type.SECP256R1WithSHA256), SECP256RConfig.Transactions, SECP256RConfig.strategy)
            testResults.secp256r.push(interim)
            testResults.aggregated.secp256r.reg += interim.registration
            testResults.aggregated.secp256r.create += interim.transactionGeneration
            testResults.aggregated.secp256r.verify += interim.transactionVerification
            accountIndex++;
        }
        testResults.aggregated.secp256r.reg /= SECP256RConfig.TokenAmount
        testResults.aggregated.secp256r.create /= SECP256RConfig.TokenAmount
        testResults.aggregated.secp256r.verify /= SECP256RConfig.TokenAmount
    }

    return testResults;
  }

  async function simulateOneToken(account, token, transactions, strategy) {
    let appIDRaw = await contract.getIdentity();
    let appID = Buffer.from(String(appIDRaw).slice(2), 'hex');
    var registrationGasUsed = await registerToken(account, token, appID);

    var testResults = {
        registration: registrationGasUsed,
        transactionGeneration: 0,
        transactionVerification: 0,
        strategy: strategy,
        rawGen: [],
        rawVer: []
    }
    if (strategy == STRATEGY.VERIFY_DIRECTLY) {
        for (var i = 0; i<transactions; i++) {
            let transactionChallengeTx = await contract.transferFunds(accounts[1], 1000, { from: account });
            var create = transactionChallengeTx.receipt.gasUsed
            testResults.transactionGeneration += create
            testResults.rawGen.push(create);
            let challenge = Buffer.from(String(transactionChallengeTx.logs[0].args.challenge).slice(2), "hex");
            var ver = await verifyTransaction(account, token, appID, challenge); 
            testResults.transactionVerification += ver
            testResults.rawVer.push(ver)
        }
    } else if (strategy == STRATEGY.VERIFY_END) {

        var challenges = []

        for (var i = 0; i<transactions; i++) {
            let transactionChallengeTx = await contract.transferFunds(accounts[1], 1000, { from: account });
            var create = transactionChallengeTx.receipt.gasUsed
            testResults.transactionGeneration += create
            testResults.rawGen.push(create)
            let challenge = Buffer.from(String(transactionChallengeTx.logs[0].args.challenge).slice(2), "hex");
            challenges.push(challenge)
        }

        for (var challenge of challenges) {
            var ver = await verifyTransaction(account, token, appID, challenge); 
            testResults.transactionVerification += ver
            testResults.rawVer.push(ver)        
          }
    }

    testResults.transactionGeneration /= transactions
    testResults.transactionVerification /= transactions


    return testResults
  }


  async function verifyTransaction(account, token, appID, challenge) {
    let keyHandleRaw = await contract.getKeyHandle({ from: account });
    let keyHandle = Buffer.from(String(keyHandleRaw).slice(2), 'hex');

    var registeredKey = {
      'version': "U2F_V2",
      'keyHandle': URLSafeBase64.encode(keyHandle)
    }

    var verificationRequest = {
      'version': 'U2F_V2',
      'type': 'u2f_sign_request',
      'appId': appID,
      'challenge': URLSafeBase64.encode(challenge),
      'registeredKeys': [registeredKey]
    };

    response = await token.HandleSignRequest(verificationRequest);

    let responseObject = getResponseObject(response.signatureData)
    let calculatedAppID = '0x' + sha2(appID);
    let userPresence = '0x' + responseObject.userPresence.toString('hex')
    let counter = '0x' + responseObject.counter.toString('hex')

    let clientData = '0x' + Buffer.from(response.clientData, 'base64').toString('hex')
    let signature = '0x' + responseObject.signature.toString('hex')

    let tx = await contract.verifyTransaction(calculatedAppID, userPresence, counter,
      clientData, signature, '0x' + challenge.toString('hex'), getAlg(token), { from: account })

    assert.equal(true, tx.logs[0].args.verified)
    return tx.receipt.gasUsed

  }


  function getResponseObject(signatureData) {
    let dataBuf = URLSafeBase64.decode(signatureData);

    return {
      'userPresence': dataBuf.slice(0, 1),
      'counter': dataBuf.slice(1, 5),
      'signature': dataBuf.slice(5),
    }
  }


  async function registerToken(account, token, appID) {
    let tx = await contract.getRegistrationChallenge({ from: account });
    let result = tx.logs[0].args
    let challenge = Buffer.from(String(result["1"]).slice(2), 'hex');

    var registrationRequest = {
        'version': 'U2F_V2',
        'type': 'u2f_register_request',
        'appId': appID,
        'registerRequests': [{
            challenge: URLSafeBase64.encode(challenge),
        }]
    };
  
    response = await token.HandleRegisterRequest(registrationRequest)

    let calculatedAppID = '0x' + sha2(appID);
    let clientData = '0x' + Buffer.from(response.clientData, 'base64').toString('hex')
    let signature = '0x' + getSignature(response.registrationData);
    let keyHandle = '0x' + response.keyHandle
    let publicKey = '0x' + getUserPublicKey(response.registrationData);
    let attestationKey = '0x' + getAttestationPublicKey(response.registrationData);

    let answerTX = await contract.answerRegistrationChallenge(calculatedAppID, clientData, 
                                                              keyHandle, publicKey, attestationKey, signature, getAlg(token), { from: account });

    assert.equal(answerTX.logs[0].args.verified, true);

    return answerTX.receipt.gasUsed + tx.receipt.gasUsed
  }

  function getAttestationPublicKey(registrationData) {

    /*
     * | Reserved (1 Byte) | PKey (65 Bytes) | KeyHandleLength (1 Byte) | KeyHandle (KeyHandleLength Bytes)
     * | Attestation Certificate (variable bytes) | signature (71-73 Bytes)
     *
     */

    let dataBuf = URLSafeBase64.decode(registrationData);
    let keyHandleLength = dataBuf.readUInt8(66);

    let startOfCertificate = 67 + keyHandleLength;

    let lengthOfCertificate = dataBuf.readUInt16BE(startOfCertificate+2) + 4;
    let endOfCertificate = startOfCertificate + lengthOfCertificate;

    let certBuffer = dataBuf.slice(startOfCertificate, endOfCertificate);

    let certRaw = parser.parse(certBuffer)
    let publicKey = certRaw.child[0].child[6].child[1].data;

    return publicKey.slice(2);
  }


  function getSignature(registrationData) {

    /*
     * | Reserved (1 Byte) | PKey (65 Bytes) | KeyHandleLength (1 Byte) | KeyHandle (KeyHandleLength Bytes)
     * | Attestation Certificate (variable bytes) | signature (71-73 Bytes)
     *
     */

    let dataBuf = URLSafeBase64.decode(registrationData);
    let keyHandleLength = dataBuf.readUInt8(66);
    let startOfCertificate = 67 + keyHandleLength;
    let lengthOfCertificate = dataBuf.readUInt16BE(startOfCertificate+2) + 4;
    let endOfCertificate = startOfCertificate + lengthOfCertificate;

    let signature = dataBuf.slice(endOfCertificate)
    return signature.toString('hex');
  }

  function getUserPublicKey(registrationData) {

    /*
     * | Reserved (1 Byte) | PKey (65 Bytes) | KeyHandleLength (1 Byte) | KeyHandle (KeyHandleLength Bytes)
     * | Attestation Certificate (variable bytes) | signature (71-73 Bytes)
     *
     */

    let dataBuf = URLSafeBase64.decode(registrationData);
    return dataBuf.slice(1, 66).toString('hex');
  }

  function sha2(message) {
    return crypto.createHash('sha256').update(message).digest().toString('hex');
  }


  function getAlg(token) {
    return (token.algo == virtualu2fToken.Type.SECP256R1WithSHA256) ? 1 : 0;
  }

});
  