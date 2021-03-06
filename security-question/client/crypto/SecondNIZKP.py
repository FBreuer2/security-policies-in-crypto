from py_ecc import bn128
from .Util import getRandomElement, hashPointsToCurve

class SecondNIZKP:
    def __init__(self, c_0_tilde_r, g_r, proof):
        self.c_0_tilde_r = c_0_tilde_r
        self.g_r = g_r
        self.proof = proof


    @staticmethod
    def generateCommitment(c_0_tilde):
        r = getRandomElement()
        c_0_tilde_r = bn128.multiply(c_0_tilde, r.n)
        g_r = bn128.multiply(bn128.G1, r.n)
        return (r, c_0_tilde_r, g_r)

    @staticmethod
    def generateProof(r, c_0_tilde_r, g_r, secretKey, challenge):
        z = (((secretKey.n * challenge.n) % bn128.curve_order) + r.n) % bn128.curve_order

        return SecondNIZKP(c_0_tilde_r, g_r, bn128.FQ(z))
