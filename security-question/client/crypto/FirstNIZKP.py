from py_ecc import bn128
from .Util import getRandomElement, hashPointsToCurve

# This NIZKP follows "Efficient Cryptographic Protocol Design Based on Distributed El Gamal Encryption" by Felix Brandt
class Proof:
    def __init__(self):
        self.isZeroEncryption = None
        self.alpha = None
        self.beta = None
        self.a1 = None
        self.b1 = None
        self.a2 = None
        self.b2 = None
        self.d1 = None
        self.d2 = None
        self.w = None
        self.publicKey = None
        self.currentD0_2i = None
        self.currentD1_2i = None
        self.secretRandomness = None

class FirstNIZKP:
    @staticmethod
    def generateCommitment(publicKey, alpha, beta, secretRandomness, currentD0_2i, currentD1_2i, isZeroEncryption):
        com = Proof()
        com.secretRandomness = secretRandomness
        com.isZeroEncryption = isZeroEncryption
        com.publicKey = publicKey
        com.alpha = alpha
        com.beta = beta
        com.currentD0_2i = currentD0_2i
        com.currentD1_2i = currentD1_2i

        if isZeroEncryption == False:
            com.r2 = getRandomElement()
            com.d2 = getRandomElement()
            com.w = getRandomElement()

            # a1 = w G
            # b1 = w H
            com.a1 = bn128.multiply(bn128.G1, com.w.n)
            com.b1 = bn128.multiply(publicKey, com.w.n)

            # a2 = r_2G + d2 beta
            com.a2 = bn128.add(bn128.multiply(bn128.G1, com.r2.n), bn128.multiply(beta, com.d2.n))
            # b2 = r_2H + d2 alpha
            com.b2 = bn128.add(bn128.multiply(publicKey, com.r2.n), bn128.multiply(alpha, com.d2.n))
        else:
            com.r1 = getRandomElement()
            com.d1 = getRandomElement()
            com.w = getRandomElement()

            # a1 = r_1 G + d1 (beta - 2iD0)
            inner = bn128.add(beta, bn128.neg(currentD0_2i))
            com.a1 = bn128.add(bn128.multiply(bn128.G1, com.r1.n), bn128.multiply(inner, com.d1.n))
            # b1 = r_1 H + d1 (alpha - 2i D_1)
            inner = bn128.add(alpha, bn128.neg(currentD1_2i))
            com.b1 = bn128.add(bn128.multiply(publicKey, com.r1.n), bn128.multiply(inner, com.d1.n))

            # a2 = w G
            # b2 = w H
            com.a2 = bn128.multiply(bn128.G1, com.w.n)
            com.b2 = bn128.multiply(publicKey, com.w.n)

        return com

    @staticmethod
    def computeProof(commitment, challenge):
        # we calculate the proof depending on which encryption we have
        if commitment.isZeroEncryption:
            commitment.d2 = bn128.FQ((challenge.n - commitment.d1.n + bn128.curve_order) % bn128.curve_order)
            commitment.r2 = bn128.FQ(((commitment.w.n - ((commitment.secretRandomness.n * commitment.d2.n) % bn128.curve_order)) + bn128.curve_order) % bn128.curve_order)
        else:
            commitment.d1 = bn128.FQ(((challenge.n - commitment.d2.n)  + bn128.curve_order) % bn128.curve_order)
            commitment.r1 = bn128.FQ(((commitment.w.n - ((commitment.secretRandomness.n * commitment.d1.n) % bn128.curve_order)) + bn128.curve_order) % bn128.curve_order)

        # now holds the proof as well
        return commitment