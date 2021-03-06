from com.Blockchain_Provider import BlockchainProvider, toChecksum
from py_ecc import bn128

import asyncio

from crypto.Util import getRandomElement, hashToCurve, hashPointsToCurve, inv
from crypto.ECC_ElGamal import ElGamal, Ciphertext

from crypto.SSS import SSS, generateSharing, getLagrange
from crypto.FirstNIZKP import FirstNIZKP
from crypto.SecondNIZKP import SecondNIZKP

providerURL = "http://127.0.0.1:8545"
contractABIPath = "./SecurityQuestionContract.json"

# Constructs the encryptions c0,i and c1,i
async def constructBinaryRepresentation(client, attemptID, elGamalInstance, dCipher, answerAttempt, p, secretKey):
    ciphertextArray = []
    nizkps = []
    publicKey = bn128.multiply(bn128.G1, secretKey.n)

    # slice leading 0b
    binaryString = bin(answerAttempt.n)[2:]
    exponent = [i for i in range(len(binaryString))]
    exponent.reverse()
    for index in range(len(binaryString)):
        random = getRandomElement()
        if binaryString[index] == '0':
            # case: beta_i = 0 => Random encryption of 0
            encryption = elGamalInstance.encrypt(0, random)
            proof = FirstNIZKP.generateCommitment(publicKey, encryption.second, encryption.first, random, dCipher.first, dCipher.second, True)
            challenge = bn128.FQ(client.getChallengeForNIZKP1(attemptID, proof))
            proof = FirstNIZKP.computeProof(proof, challenge)
            ciphertextArray.append(encryption)
            nizkps.append(proof)
        else:
            element = (bn128.FQ(2) ** exponent[index]).n
            # c0,i = d_0 ** (2**i * beta_i) * (g_1 ** r) | case: beta_i = 1
            d0pow = bn128.multiply(dCipher.first, element)
            gr = bn128.multiply(bn128.G1, random.n)
            c0i = bn128.add(d0pow, gr)
            
            # c1,i = d_1 ** (2**i * beta_i) * (h ** r) | case: beta_i = 1
            d1pow = bn128.multiply(dCipher.second, element)
            hr = bn128.multiply(elGamalInstance.publicKey, random.n)
            c1i = bn128.add(d1pow, hr)

            proof = FirstNIZKP.generateCommitment(publicKey, c1i, c0i, random, dCipher.first, dCipher.second, False)
            challenge = bn128.FQ(client.getChallengeForNIZKP1(attemptID, proof))
            proof = FirstNIZKP.computeProof(proof, challenge)

            encryption = Ciphertext(c0i, c1i)
            ciphertextArray.append(encryption)
            nizkps.append(proof)

    return (ciphertextArray, nizkps)

async def constructPartyPart(senderAddress, ciphertext, challenge, secretKeyPart, x, client, attemptID):
    psi = getRandomElement()

    c0I = bn128.multiply(bn128.multiply(ciphertext.first, psi.n), secretKeyPart.n)
    k_i = bn128.multiply(bn128.multiply(bn128.G2, challenge.n), inv(psi.n, bn128.curve_order))

    com = SecondNIZKP.generateCommitment(ciphertext.first)
    challenge = bn128.FQ(client.getChallengeNZIK2(attemptID, com[1], com[2], bn128.FQ(x)))

    nzik2 = SecondNIZKP.generateProof(com[0], com[1], com[2], secretKeyPart, challenge)

    cost = client.verifyNZIK2(attemptID, senderAddress, nzik2.c_0_tilde_r, nzik2.g_r, nzik2.proof)

    return (c0I, k_i, nzik2, cost)

async def run(threshold, amount, runID, contractAddress):

    runtimeInfo = {}

    accounts = BlockchainProvider.getAccounts(providerURL)
    secretKeys = []
    members = []

    client = BlockchainProvider(providerURL, contractABIPath, contractAddress, accounts[10+runID])

    # Setup secret sharing and generate a sharing for the parties
    secretKey = getRandomElement()
    publicKey = bn128.multiply(bn128.G1, secretKey.n)

    shares = generateSharing(secretKey, threshold, amount)

    p = getRandomElement()

    # a is the input string a user would give, mapped into FQ. For this prototype we just use a random value. 
    a = getRandomElement()
    elGamalInstance = ElGamal(publicKey)
    dCipher = elGamalInstance.encrypt(p)
    cCipher = elGamalInstance.encryptC(a, p) 

    for i in range(amount):
        members.append(toChecksum(accounts[i+1]))
        secretKeys.append(shares[i].y)

    # Create the group
    runtimeInfo['GroupCreation'] = client.createCommittee(members, amount, cCipher, dCipher, None)
    print("Group with ", amount, " members created!")

    runtimeInfo['AddKey'] = 0
    runtimeInfo['AddPart'] = 0
    runtimeInfo['PoK1'] = 0
    runtimeInfo['PoK2'] = 0
    runtimeInfo['Validation'] = 0

    # Each party posts its public keys
    for i in range(amount):
        cost = client.addKey(bn128.multiply(bn128.G1, secretKeys[i].n), members[i])
        runtimeInfo['AddKey'] += cost
        runtimeInfo['GroupCreation'] += cost

    print("Constructing query. This will take a while ...")

    # For now we only want to send one attempt
    attemptIDAsBytes = bytes('0x' + str(1), 'utf8')

    # Construct the query as encryption of the binary encoding
    encodedQuery = await constructBinaryRepresentation(client, attemptIDAsBytes, elGamalInstance, dCipher, a, p, secretKey)

    # Add up the binary encoding and calculate c0_tilde and c1_tilde
    addedCiphertexts = encodedQuery[0][0]
    for i in range(len(encodedQuery[0])):
        if i != 0:
            addedCiphertexts *= encodedQuery[0][i]

    cTilde = cCipher * addedCiphertexts

    challenge = bn128.FQ(client.getKScalar(attemptIDAsBytes))
    k = bn128.multiply(bn128.G2, challenge.n)

    runtimeInfo['Query'] = client.query(attemptIDAsBytes, encodedQuery[0], encodedQuery[1], cTilde.first, cTilde.second, k)

    print("Query sent")


    xOthers = []
    for x in range(1, amount+1):
        xOthers.append(bn128.FQ(x))

    # each party now calculates its parts based on its secret key
    for i in range(amount):
        partyPartSingle = await constructPartyPart(members[i], cTilde, challenge, shares[i].y, i+1, client, attemptIDAsBytes)
        cost = client.addPart(attemptIDAsBytes, members[i], partyPartSingle[0], partyPartSingle[1])
        runtimeInfo['AddPart'] += cost
        runtimeInfo['Validation'] += cost + partyPartSingle[3]

    print("Parties have submitted their parts")
    await asyncio.sleep(1)

    runtimeInfo['Verify'] = client.verdict(attemptIDAsBytes)

    return runtimeInfo

async def start():
    csvFile = open("benchmark_results.csv", "w")
    csvFile.write("Group size;Threshold;Group Creation with key commitment;Client query; Miner Validation; Client verification\n")

    contractAddress = BlockchainProvider.deployNew(providerURL, contractABIPath)

    for i in range(2, 40):
        stats = await run(i, i, i, contractAddress)
        csvFile.write(str(i) + ";"+ str(i) + ";" + toDollar(stats['GroupCreation']) +
        ";" + toDollar(stats['Query']) + ";" + toDollar(stats['Validation']) + ";" + toDollar(stats['Verify']) + "\n")
        csvFile.flush()

def toDollar(amountInGwei):
    amountInEther = amountInGwei/1000000000
    cost = amountInEther*180
    costAsString = "{:.4f}".format(cost).replace(".", ",")
    return costAsString

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(start())
