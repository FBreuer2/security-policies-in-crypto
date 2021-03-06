import secrets
from py_ecc import bn128
import hashlib

def getRandomElement():
    newElement = 0
    while (newElement == 0 or newElement == 1):
        newElement = secrets.randbelow(bn128.curve_order)
    return bn128.FQ(newElement)
    
def hashToCurve(message):
    return bn128.FQ((int(hashlib.sha256(message).hexdigest(), 16) % bn128.curve_order))

# Really think if you want to do it this way in a real world application
def hashPointsToCurve(points):
    hashableString = ""

    for point in points:
        hashableString += repr(point[0]) + repr(point[1])

    hashableString = hashableString.encode('utf-8')

    return bn128.FQ((int(hashlib.sha256(hashableString).hexdigest(), 16) % bn128.curve_order))

def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n