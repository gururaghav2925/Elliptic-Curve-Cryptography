# Elliptic-Curve-Cryptography
Elliptic Curve Cryptography (ECC) is a public-key cryptographic system based on the algebraic structure of elliptic curves over finite fields.
The security of ECC relies on the difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP).Core OperationsThe key concepts in ECC are:Point Addition ($P + Q = R$):
A line through points $P$ and $Q$ intersects the curve at a third point, $R'$. Reflecting $R'$ across the x-axis gives $R$.Point Doubling ($P + P = 2P$):
A tangent line at point $P$ intersects the curve at a second point, $R'$. 
Reflecting $R'$ across the x-axis gives $2P$.Scalar Multiplication ($kP$): Repeated point addition and doubling, representing the private key ($k$).Implementation Concept (Python Example)A simplified implementation would involve defining the curve parameters and the scalar multiplication function.
Python# Conceptual Python Code for ECC (Requires a robust math library for real implementation)

# This example is highly simplified for illustration.
```py
# ecc_elgamal_demo.py
# Educational demo: Elliptic Curve arithmetic + EC-ElGamal and classic ElGamal (mod p)
# Not production-ready.

import random
from typing import Optional, Tuple

# -------------------------
# Helpers: modular arith
# -------------------------
def inv_mod(a: int, p: int) -> int:
    """Modular inverse using extended Euclid"""
    if a % p == 0:
        raise ZeroDivisionError("no inverse")
    return pow(a, -1, p)

def legendre_symbol(a: int, p: int) -> int:
    return pow(a, (p - 1) // 2, p)

def tonelli_shanks(n: int, p: int) -> Optional[int]:
    """Return a square root of n mod p if exists, else None. (p must be odd prime)"""
    if n == 0:
        return 0
    if p == 2:
        return n
    ls = legendre_symbol(n, p)
    if ls == p - 1:  # -1 mod p
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    # Factor p-1 as q * 2^s
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    # find z which is a quadratic non-residue
    z = 2
    while legendre_symbol(z, p) != p - 1:
        z += 1
    c = pow(z, q, p)
    x = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    while t != 1:
        # find least i (0 < i < m) s.t. t^(2^i) == 1
        i = 1
        tt = pow(t, 2, p)
        while tt != 1:
            tt = pow(tt, 2, p)
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        c = pow(b, 2, p)
        t = (t * c) % p
        m = i
    return x

# -------------------------
# Elliptic Curve over F_p
# -------------------------
Point = Optional[Tuple[int, int]]  # None is point-at-infinity

class Curve:
    def __init__(self, a: int, b: int, p: int, G: Tuple[int,int], n: Optional[int]=None, name: str="curve"):
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n  # order of G if known
        self.name = name

    def is_on_curve(self, P: Point) -> bool:
        if P is None:
            return True
        x, y = P
        return (y*y - (x*x*x + self.a * x + self.b)) % self.p == 0

    def point_neg(self, P: Point) -> Point:
        if P is None:
            return None
        x, y = P
        return (x, (-y) % self.p)

    def point_add(self, P: Point, Q: Point) -> Point:
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        p = self.p
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P != Q:
            s = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
        else:
            if y1 == 0:
                return None
            s = ((3 * x1 * x1 + self.a) * inv_mod((2 * y1) % p, p)) % p
        x3 = (s*s - x1 - x2) % p
        y3 = (s*(x1 - x3) - y1) % p
        return (x3, y3)

    def scalar_mult(self, k: int, P: Point) -> Point:
        if k % (self.n or self.p) == 0 or P is None:
            return None
        if k < 0:
            return self.scalar_mult(-k, self.point_neg(P))
        result = None
        addend = P
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result

# -------------------------
# Message encoding to point (simple)
# -------------------------
def encode_int_to_point(curve: Curve, m: int, max_tries=1000) -> Point:
    """Try x = m, m+1, ... until x^3+ax+b is quadratic residue. Return point."""
    p = curve.p
    for k in range(max_tries):
        x = (m + k) % p
        rhs = (x*x*x + curve.a * x + curve.b) % p
        y = tonelli_shanks(rhs, p)
        if y is not None:
            return (x, y)
    raise ValueError("Failed to encode message as point")

def decode_point_to_int(curve: Curve, P: Point) -> int:
    """Recover x as integer payload (the original m will be x minus the offset unknown).
       For our encode scheme we assume the original small integer is near x."""
    if P is None:
        raise ValueError("Cannot decode infinity")
    x, y = P
    return x  # user must know mapping; in demo we used m -> x

# -------------------------
# EC-ElGamal (toy)
# -------------------------
def ec_keygen(curve: Curve) -> Tuple[int, Point]:
    priv = random.randrange(1, curve.n if curve.n else curve.p)
    pub = curve.scalar_mult(priv, curve.G)
    return priv, pub

def ec_encrypt(curve: Curve, pub: Point, M_point: Point) -> Tuple[Point, Point]:
    k = random.randrange(1, curve.n if curve.n else curve.p)
    C1 = curve.scalar_mult(k, curve.G)
    kQ = curve.scalar_mult(k, pub)
    # point addition as "message + kQ"
    C2 = curve.point_add(M_point, kQ)
    return C1, C2

def ec_decrypt(curve: Curve, priv: int, C1: Point, C2: Point) -> Point:
    s = curve.scalar_mult(priv, C1)  # s = priv * C1 = priv * kG = k * priv * G = kQ
    s_neg = curve.point_neg(s)
    M = curve.point_add(C2, s_neg)
    return M

# -------------------------
# Classic ElGamal mod p
# -------------------------
def classic_keygen(p: int, g: int) -> Tuple[int, int]:
    x = random.randrange(2, p-1)
    y = pow(g, x, p)
    return x, y

def classic_encrypt(p: int, g: int, y: int, m: int) -> Tuple[int, int]:
    k = random.randrange(2, p-1)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2

def classic_decrypt(p: int, x: int, c1: int, c2: int) -> int:
    s = pow(c1, x, p)
    s_inv = inv_mod(s, p)
    m = (c2 * s_inv) % p
    return m

# -------------------------
# Demo usage
# -------------------------
if __name__ == "__main__":
    # Example curve: small toy curve (safe only for learning)
    # curve: y^2 = x^3 + ax + b over prime p
    # We'll use small parameters:
    p = 9739
    a = 497
    b = 1768
    G = (1804, 5368)
    # example order n (not checked here, just for scalar limits)
    curve = Curve(a=a, b=b, p=p, G=G, n=  9551, name="toy-curve")

    assert curve.is_on_curve(G), "G not on curve"

    # EC keygen
    priv, pub = ec_keygen(curve)
    print("EC priv:", priv)
    print("EC pub:", pub)

    # Encode integer message -> point
    message_int = 42
    M_point = encode_int_to_point(curve, message_int)
    print("Encoded point for", message_int, "->", M_point)
    # Encrypt
    C1, C2 = ec_encrypt(curve, pub, M_point)
    print("EC C1:", C1)
    print("EC C2:", C2)
    # Decrypt
    M_rec = ec_decrypt(curve, priv, C1, C2)
    print("Decrypted point:", M_rec)
    print("Decoded int (x):", decode_point_to_int(curve, M_rec))

    # Classic ElGamal demo (mod p)
    # small safe prime (toy)
    p2 = 467
    # choose generator g of multiplicative group mod p2 (we assume 2 is primitive for demo)
    g2 = 2
    x2, y2 = classic_keygen(p2, g2)
    print("\nClassic ElGamal priv(x):", x2, "pub(y):", y2)
    m_plain = 123 % p2
    c1, c2 = classic_encrypt(p2, g2, y2, m_plain)
    print("Classic cipher:", (c1, c2))
    m_rec = classic_decrypt(p2, x2, c1, c2)
    print("Classic decrypted:", m_rec)

```
# Output :
