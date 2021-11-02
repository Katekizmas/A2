import collections
import random
import hashlib


EllipticCurve = collections.namedtuple('EllipticCurve', 'p a b G n h')

curve = EllipticCurve(
    p = (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff), # Curve coefficients.
    a = (0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc), # Curve coefficient 'a'.
    b = (0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b), # Curve coefficient 'b'.
    G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5), # Base point.
    n = (0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551), # Subgroup order.
    h = (0x1), # Subgroup cofactor.
)

# Functions that work on curve points
def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0 


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * pow(x1 - x2, -1, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p, -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result

def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result

# Methods for generating keypair, signing and verifying
def generate_keypair():
    dA = random.randint(1, curve.n - 1) # private key
    QA = scalar_mult(dA, curve.G) # public key

    return dA, QA

def sign_data(e, dA):
    k = random.randint(1, curve.n - 1)
    x1, y1 = scalar_mult(k, curve.G)

    r = x1 % curve.n
    if r == 0:
      raise RuntimeError("r is zero. Please repeat")

    s = (pow(k, -1, curve.n) * (e + r * dA)) % curve.n
    if s == 0:
      raise RuntimeError("s is zero. Please repeat")

    return r, s

def verify_data(e, QA, r, s):
    if r < 1 or r > curve.n - 1:
      return 0, False
    if s < 1 or s > curve.n - 1:
      return 0, False
    
    c = pow(s, -1, curve.n)
    u1 = (e * c) % curve.n
    u2 = (r * c) % curve.n

    x1, y1 = point_add(scalar_mult(u1,curve.G), scalar_mult(u2,QA))

    v = x1 % curve.n

    return v, v == r