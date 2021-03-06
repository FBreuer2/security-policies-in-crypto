from py_ecc import bn128
from .Util import getRandomElement, inv

def getLagrange(x, others):
    product = 1

    for xOther in others:
        if x != xOther.n:
            upperTerm = (-(xOther.n) + bn128.curve_order) % bn128.curve_order
            lowerTerm = inv(((x - xOther.n) + bn128.curve_order) % bn128.curve_order, bn128.curve_order)
            product = (product * ((upperTerm * lowerTerm) % bn128.curve_order) % bn128.curve_order)
    
    return bn128.FQ(product)

class Share:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def interpolate(self, others):
        return bn128.multiply(bn128.multiply(bn128.G1, self.y.n), getLagrange(self.x, others).n)

class Polynom:
    def __init__(self, secret, threshold):
        self.coefficients = []

        self.coefficients.append(secret)

        for _ in range(1, threshold):
            self.coefficients.append(getRandomElement())

    def getShares(self, amount):
        shares = []

        for x in range(1, amount + 1):
            shares.append(Share(x, self.evaluate(x)))

        return shares


    def evaluate(self, x):
        result = 0
        i = 0

        for coefficient in self.coefficients:
            result = (result + (coefficient.n * pow(x, i, bn128.curve_order))) % bn128.curve_order
            i += 1

        return bn128.FQ(result % bn128.curve_order)


class SSS:
    def __init(self):
        return

    def newPolynom(self, secret, threshold):
        return Polynom(secret, threshold)


def generateSharing(key, threshold, amount):
    secretSharing = SSS()
    currentPolynom = secretSharing.newPolynom(key, threshold)
    return currentPolynom.getShares(amount)