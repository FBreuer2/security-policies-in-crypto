from py_ecc import bn128
from .Util import getRandomElement

class Ciphertext:
    def __init__(self, c0, c1):
        self.first = c0
        self.second = c1
    
    def __mul__(self, other):
        return Ciphertext(bn128.bn128_curve.add(self.first, other.first), bn128.bn128_curve.add(self.second, other.second))

    @staticmethod
    def fromBlockchain(array):
        return Ciphertext((bn128.FQ(array[0][0]), bn128.FQ(array[0][1])), (bn128.FQ(array[1][0]), bn128.FQ(array[1][1])))

    def __repr__(self): 
        return '(x: %s y: %s,\n x: %s y: %s' % (repr(self.first[0]), repr(self.first[1]), repr(self.second[0]), repr(self.second[1]))     

class ElGamal:
    def __init__(self, publicKey):
        self.publicKey = publicKey
        return

    def encrypt(self, message, random = None):
        if random is None:
            random = getRandomElement().n
        else:
            random = random.n

        hR = bn128.bn128_curve.multiply(self.publicKey, random)

        if (message == 0):
            return Ciphertext(bn128.bn128_curve.multiply(bn128.G1, random), hR)

        gM = bn128.bn128_curve.multiply(bn128.G1, message.n)

        return Ciphertext(bn128.bn128_curve.multiply(bn128.G1, random), bn128.bn128_curve.add(hR, gM))

    def encryptC(self, a, p):
        random = getRandomElement().n
        hR = bn128.bn128_curve.multiply(self.publicKey, random)
        gM = bn128.multiply(bn128.multiply(bn128.G1, a.n), p.n)

        return Ciphertext(bn128.bn128_curve.multiply(bn128.G1, random), bn128.bn128_curve.add(hR, bn128.neg(gM)))

    @staticmethod
    def decrypt(secretKey, ciphertext):
        grx = bn128.bn128_curve.multiply(ciphertext.c1, secretKey.n)
        return bn128.bn128_curve.add(bn128.neg(grx), ciphertext.c2)