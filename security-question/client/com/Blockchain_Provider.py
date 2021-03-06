from web3 import Web3, HTTPProvider
import json
import asyncio


def toChecksum(address):
    return Web3.toChecksumAddress(address)


# eth module gets attached at runtime, so the errors here can be ignored
class BlockchainProvider:
    def __init__(self, url, contractABIPath, contractAddress, senderAddress = None):
        self.url = url
        self.contractABIPath = contractABIPath
        self.contractAddress = contractAddress
        self.w3 = Web3(HTTPProvider(url, request_kwargs={'timeout':100}))
        self.filters = []
        self.finished = None

        if senderAddress == None:
            self.mainGroup = self.w3.eth.accounts[0]
            self.w3.eth.defaultAccount = self.w3.eth.accounts[0]
        else:
            self.mainGroup = senderAddress
            self.w3.eth.defaultAccount = senderAddress

        with open(contractABIPath) as contractFile:
            contractData = json.load(contractFile)
            bytecode = contractData['bytecode']
            abi = contractData["abi"]
            self.contractInstance = self.w3.eth.contract(address=contractAddress, abi=abi)


    @staticmethod
    def deployNew(url, contractABIPath):
        w = Web3(HTTPProvider(url, request_kwargs={'timeout':100}))
        w.eth.defaultAccount = w.eth.accounts[0]

        with open(contractABIPath) as contractFile:
            contractData = json.load(contractFile)
            bytecode = contractData['bytecode']
            abi = contractData["abi"]
            contractInstance = w.eth.contract(abi=abi, bytecode=bytecode)
            tx = contractInstance.constructor().transact()
            receipt = w.eth.waitForTransactionReceipt(tx)

            return receipt.contractAddress


    @staticmethod
    def getAccounts(url):
        w = Web3(HTTPProvider(url))
        return w.eth.accounts

    def createCommittee(self, members, threshold, c, d, finished):
        c0 = [c.first[0].n, c.first[1].n]
        c1 = [c.second[0].n, c.second[1].n]

        d0 = [d.first[0].n, d.first[1].n]
        d1 = [d.second[0].n, d.second[1].n]

        tx = self.contractInstance.functions.createCommittee(members, threshold, c0, c1, d0, d1).transact()
        receipt = self.w3.eth.waitForTransactionReceipt(tx)

        self.finished = finished
        return receipt['gasUsed']

    def addKey(self, key, senderAddress):
        self.w3.eth.defaultAccount = senderAddress
        tx = self.contractInstance.functions.addKeyForMember(self.mainGroup, [key[0].n, key[1].n]).transact()
        self.w3.eth.defaultAccount = self.mainGroup

        receipt = self.w3.eth.waitForTransactionReceipt(tx)
        return receipt['gasUsed']

#    function query(bytes memory id, uint[2][] memory c0, uint[2][] memory c1, uint[2] c_0_tilde, uint[2] c_1_tilde, uint[2][2] memory k

    def query(self, attemptID, ciphertexts, nizkps, c_0_tilde, c_1_tilde, k):
        c0 = []
        c1 = []
        r1 = []
        r2 = []
        d1 = []
        d2 = []
        a1 = []
        a2 = []
        b1 = []
        b2 = []

        blockchain_c0_tilde = [c_0_tilde[0].n, c_0_tilde[1].n]
        blockchain_c1_tilde = [c_1_tilde[0].n, c_1_tilde[1].n]

        for ciphertext in ciphertexts:
            c0.append([ciphertext.first[0].n, ciphertext.first[1].n])
            c1.append([ciphertext.second[0].n, ciphertext.second[1].n])
        
        for nizkp in nizkps:
            a1.append([nizkp.a1[0].n, nizkp.a1[1].n])
            a2.append([nizkp.a2[0].n, nizkp.a2[1].n])
            b1.append([nizkp.b1[0].n, nizkp.b1[1].n])
            b2.append([nizkp.b2[0].n, nizkp.b2[1].n])
            r1.append(nizkp.r1.n)
            r2.append(nizkp.r2.n)
            d1.append(nizkp.d1.n)
            d2.append(nizkp.d2.n)

        kCoeffs = [[k[0].coeffs[1].n, k[0].coeffs[0].n], [k[1].coeffs[1].n, k[1].coeffs[0].n]]

        self.w3.eth.defaultAccount = self.mainGroup
        tx = self.contractInstance.functions.query(attemptID, c0, c1, blockchain_c0_tilde, blockchain_c1_tilde, kCoeffs).transact()
        receipt = self.w3.eth.waitForTransactionReceipt(tx)
        
        gasUsed = receipt['gasUsed']

        tx = self.contractInstance.functions.broadcastNIZKP1(self.mainGroup, attemptID, a1, b1, a2, b2).transact()
        receipt = self.w3.eth.waitForTransactionReceipt(tx)
        gasUsed += receipt['gasUsed']


        tx = self.contractInstance.functions.broadcastNIZKP2(self.mainGroup, attemptID, d1, d2, r1, r2).transact()
        receipt = self.w3.eth.waitForTransactionReceipt(tx)
        gasUsed += receipt['gasUsed']

        return gasUsed


    def getChallengeForNIZKP1(self, attemptID, nizkCommitment):
        a1 = [nizkCommitment.a1[0].n, nizkCommitment.a1[1].n]
        a2 = [nizkCommitment.a2[0].n, nizkCommitment.a2[1].n]
        b1 = [nizkCommitment.b1[0].n, nizkCommitment.b1[1].n]
        b2 = [nizkCommitment.b2[0].n, nizkCommitment.b2[1].n]

        tx = self.contractInstance.functions.getChallengeForNZIK1(self.mainGroup, attemptID, a1, b1, a2, b2).call()
        return tx

#    function (address group, bytes memory id, 
#                    uint[2] memory c_0_i, uint[2][2] memory k_i) 
    def addPart(self, attemptID, senderAddress, c_0_i, k_i):
        self.w3.eth.defaultAccount = senderAddress


        blockchain_c0i = [c_0_i[0].n, c_0_i[1].n]

        k_iCoeffs = [[k_i[0].coeffs[1].n, k_i[0].coeffs[0].n], [k_i[1].coeffs[1].n, k_i[1].coeffs[0].n]]

        tx = self.contractInstance.functions.addPart(self.mainGroup, attemptID, blockchain_c0i, k_iCoeffs).transact()
        self.w3.eth.defaultAccount = self.mainGroup

        receipt = self.w3.eth.waitForTransactionReceipt(tx)
        return receipt['gasUsed']


    def getKScalar(self, attemptIDAsBytes):
        self.w3.eth.defaultAccount = self.mainGroup

        scalar = self.contractInstance.functions.getKScalar(self.mainGroup, attemptIDAsBytes).call()

        return scalar
    

    #address group, bytes memory id, uint[2] memory cR, uint[2] memory gR, uint z, uint xMember
    def getChallengeNZIK2(self, attemptID, cR, gR, x):
        challenge = self.contractInstance.functions.getChallengeForNZIK2(self.mainGroup, attemptID, [cR[0].n, cR[1].n], [gR[0].n, gR[1].n], x.n).call()
        return challenge

    #verifyNZIK2(address group, bytes memory id, uint z, uint[2] memory cR)
    def verifyNZIK2(self, attemptID, senderAddress, cR, gR, z):
        self.w3.eth.defaultAccount = senderAddress

        tx = self.contractInstance.functions.verifyNZIK2(self.mainGroup, attemptID, [cR[0].n, cR[1].n], [gR[0].n, gR[1].n], z.n).transact()
        self.w3.eth.defaultAccount = self.mainGroup

        receipt = self.w3.eth.waitForTransactionReceipt(tx)
        return receipt['gasUsed']


    def verdict(self, attemptId):
        self.w3.eth.defaultAccount = self.mainGroup
        tx = self.contractInstance.functions.verdict(attemptId).transact({"gas": 6721975})

        receipt = self.w3.eth.waitForTransactionReceipt(tx)
        return receipt['gasUsed']

    def getAccount(self):
        return self.w3.eth.defaultAccount

    def getGroup(self):
        return self.mainGroup