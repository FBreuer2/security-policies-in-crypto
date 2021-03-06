pragma solidity > 0.4.21;

import "./ECC.sol";
import "./HelperLibrary.sol";


contract BankAccounts {
    bytes32 _identity;
    address _owner;
    ChainType _deployedChainType;
    uint _randNonce;

    enum ChainType { Sim, Test, Main }
    enum RequestType {Registration, Authentication}
    enum SigningAlgorithm {Secp256k1WithKeccak256, Secp256r1WithSHA256}

    event NewRegistrationChallenge(address account, bytes32 challenge);
    event NewRegistrationStatus(address account, bool verified);

    event NewTransactionsChallenge(address account, bytes32 challenge);
    event NewTransactionStatus(address to, uint amount, bool verified);

    mapping(address => BankAccount) _bankAccounts;

    struct Transaction {
        address beneficiary;
        uint64 amount;
        uint64 transactionTime;

        bytes32 transactionChallenge;
        bool verified;
    }

    struct BankAccount {
        // U2F
        bool isVerified;
        bytes32 registrationChallenge;

        bytes registeredPublicKey;
        bytes keyHandle;


        // account data
        uint64 currentBalance;

        // delayed transactions
        Transaction[] _delayedTransactions;
    }

    constructor(ChainType chainType) public {
		_randNonce = 0;
		_owner = msg.sender;
        _deployedChainType = chainType;
        _identity = "tttttttttttttttttttttttttttttttt";
	}

    // getRegistrationChallenge generates a challenge for the U2F Client to construct a RegistrationRequest object
    function getRegistrationChallenge() public payable {
        require(_bankAccounts[msg.sender].isVerified == false, "Only unverified accounts can request registration.");

        // first create the random part of the challenge
        bytes32 randomChallenge = getRandom();

        // then create the hash that a valid response should have
        _bankAccounts[msg.sender].registrationChallenge = sha256(abi.encodePacked(RequestType.Registration, msg.sender, randomChallenge, _identity));

        emit NewRegistrationChallenge(msg.sender, _bankAccounts[msg.sender].registrationChallenge);
    }


    // answerRegistrationChallenge checks if a) the challenge was the correct one and b) signature matches the supplied attestation key
    function answerRegistrationChallenge(bytes32 applicationParameter, bytes clientData, bytes keyHandle,
                                                  bytes userPublicKey, bytes attestationKey, bytes signature, SigningAlgorithm signingAlgorithm) public {

        require(_bankAccounts[msg.sender].isVerified == false, "Only unverified accounts can respond to challenges");
        require(HelperLibrary.verifyCorrectChallenge(clientData, _bankAccounts[msg.sender].registrationChallenge),
                                                     "Wrong challenge in ClientData");

        // check if the application identity matches
        require(sha256(abi.encodePacked(_identity)) == applicationParameter, "Application identity does not match.");

        bytes32 challengeParameter = sha256(clientData);
        
        // construct the message which the U2F Token/Client should have signed correctly
        bytes memory message = new bytes(1+applicationParameter.length+challengeParameter.length+keyHandle.length+userPublicKey.length);

        // first part of the message is reserved and not used yet
        message[0] = byte(0);

        // add data to message object
        uint messageIndex = 1;

		for (uint i = 0; i < applicationParameter.length; i++) {
			message[messageIndex++] = applicationParameter[i];
		}
		for (i = 0; i < challengeParameter.length; i++) {
			message[messageIndex++] = challengeParameter[i];
		}
		for (i = 0; i < keyHandle.length; i++) {
			message[messageIndex++] = keyHandle[i];
		}
		for (i = 0; i < userPublicKey.length; i++) {
			message[messageIndex++] = userPublicKey[i];
		}

        bool goodSignature = false;

        // check the signature with the specified algorithm
        if (signingAlgorithm == SigningAlgorithm.Secp256k1WithKeccak256) {
            goodSignature = ECC.verifyECRecover(keccak256(message), attestationKey, signature);
        } else if (signingAlgorithm == SigningAlgorithm.Secp256r1WithSHA256) {
            goodSignature = ECC.verifySECP256R1(sha256(message), attestationKey, signature);
        }

        if (goodSignature) {
            _bankAccounts[msg.sender].isVerified = true;
            _bankAccounts[msg.sender].registeredPublicKey = userPublicKey;
            _bankAccounts[msg.sender].keyHandle = keyHandle;
        }

       emit NewRegistrationStatus(msg.sender, goodSignature);
    }


    function transferFunds(address to, uint64 amount) public payable {
        // XXX: check balance here
        //require(_bankAccounts[msg.sender].currentBalance >= amount, "Not enough funds!");
        //_bankAccounts[msg.sender].currentBalance -= amount;

        bytes32 randomChallenge = getRandom();

        Transaction memory newTransaction;
        newTransaction.beneficiary = to;
        newTransaction.amount = amount;
        newTransaction.transactionTime = 0;
        newTransaction.transactionChallenge = sha256(abi.encodePacked(newTransaction.beneficiary, newTransaction.amount,
                                                                      newTransaction.transactionTime, RequestType.Registration,
                                                                      randomChallenge, _identity));

        bool hasBeenInserted = false;

        for (uint i = 0; i<_bankAccounts[msg.sender]._delayedTransactions.length; i++) {
            if (_bankAccounts[msg.sender]._delayedTransactions[i].verified == true) {
                _bankAccounts[msg.sender]._delayedTransactions[i] = newTransaction;
                hasBeenInserted = true;
            }
        }

        if (!hasBeenInserted)
            _bankAccounts[msg.sender]._delayedTransactions.push(newTransaction);

        // then create the hash that a valid response should have
        emit NewTransactionsChallenge(msg.sender, newTransaction.transactionChallenge);
    }


    function verifyTransaction(bytes32 applicationParameter, bytes1 userPresence, bytes4 counter,
                               bytes clientData, bytes signature, bytes32 transactionChallenge, SigningAlgorithm signingAlgorithm) public payable {
        require(_bankAccounts[msg.sender].isVerified == true, "Only verified accounts can respond to transaction challenges");

        // check if the application identity matches
        require(sha256(abi.encodePacked(_identity)) == applicationParameter, "Application identity does not match.");

        bytes32 challengeParameter = sha256(clientData);

        // construct the message which the U2F Token/Client should have signed correctly
        bytes memory message = new bytes(applicationParameter.length+userPresence.length+counter.length+challengeParameter.length);

        // add data to message object
        uint messageIndex = 0;

		for (uint l = 0; l < applicationParameter.length; l++) {
			message[messageIndex++] = applicationParameter[l];
		}
		for (l = 0; l < userPresence.length; l++) {
			message[messageIndex++] = userPresence[l];
		}
		for (l = 0; l < counter.length; l++) {
			message[messageIndex++] = counter[l];
		}
		for (l = 0; l < challengeParameter.length; l++) {
			message[messageIndex++] = challengeParameter[l];
		}

        bool goodSignature = false;

        // check the signature with the specified algorithm
        if (signingAlgorithm == SigningAlgorithm.Secp256k1WithKeccak256) {
            goodSignature = ECC.verifyECRecover(keccak256(message), _bankAccounts[msg.sender].registeredPublicKey, signature);
        } else if (signingAlgorithm == SigningAlgorithm.Secp256r1WithSHA256) {
            goodSignature = ECC.verifySECP256R1(sha256(message), _bankAccounts[msg.sender].registeredPublicKey, signature);
        }

        if (goodSignature) {
            for (uint i = 0; i<_bankAccounts[msg.sender]._delayedTransactions.length; i++) {
                if (_bankAccounts[msg.sender]._delayedTransactions[i].transactionChallenge == transactionChallenge) {
                    require(HelperLibrary.verifyCorrectChallenge(clientData,
                                                                transactionChallenge),
                                                                "Wrong challenge in ClientData");

                    _bankAccounts[msg.sender]._delayedTransactions[i].verified = true;
                    emit NewTransactionStatus(_bankAccounts[msg.sender]._delayedTransactions[i].beneficiary,
                                               _bankAccounts[msg.sender]._delayedTransactions[i].amount,
                                               true);

                    return;
                }
            }
        }

        emit NewTransactionStatus(_bankAccounts[msg.sender]._delayedTransactions[i].beneficiary,
                                  _bankAccounts[msg.sender]._delayedTransactions[i].amount,
                                  false);
    }

    function getRandom() private view returns (bytes32 random) {
        _randNonce++;
        return bytes32(keccak256(abi.encodePacked(this, msg.sender, blockhash(block.number - 1), block.number - 1,
                                                  block.coinbase, block.difficulty, _randNonce)));
    }

    function getKeyHandle() public view returns (bytes handle) {
        return _bankAccounts[msg.sender].keyHandle;
    }

    function getIdentity() public view returns (bytes32 identity) {
        return _identity;
    }
}
