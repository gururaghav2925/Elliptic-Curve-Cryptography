# Elliptic-Curve-Cryptography
Elliptic Curve Cryptography (ECC) is a public-key cryptographic system based on the algebraic structure of elliptic curves over finite fields.
The security of ECC relies on the difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP).Core OperationsThe key concepts in ECC are:Point Addition ($P + Q = R$):
A line through points $P$ and $Q$ intersects the curve at a third point, $R'$. Reflecting $R'$ across the x-axis gives $R$.Point Doubling ($P + P = 2P$):
A tangent line at point $P$ intersects the curve at a second point, $R'$. 
Reflecting $R'$ across the x-axis gives $2P$.Scalar Multiplication ($kP$): Repeated point addition and doubling, representing the private key ($k$).Implementation Concept (Python Example)A simplified implementation would involve defining the curve parameters and the scalar multiplication function.
Python# Conceptual Python Code for ECC (Requires a robust math library for real implementation)

# This example is highly simplified for illustration.
```py
import random

# Elliptic Curve over Fp: y^2 = x^3 + a*x + b
class Curve:
    def __init__(self, a, b, p, G):
        self.a = a
        self.b = b
        self.p = p
        self.G = G

    def inv_mod(self, k):
        return pow(k, -1, self.p)

    def add(self, P, Q):
        if P is None: return Q
        if Q is None: return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            return None

        if P == Q:
            s = ((3 * x1 * x1 + self.a) * self.inv_mod(2 * y1)) % self.p
        else:
            s = ((y2 - y1) * self.inv_mod(x2 - x1)) % self.p

        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mult(self, k, P):
        R = None
        while k > 0:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R


# Example parameters
p = 9739
a = 497
b = 1768
G = (1804, 5368)

curve = Curve(a, b, p, G)

# Key generation
private_key = random.randint(1, p - 1)
public_key = curve.mult(private_key, G)

print("Private Key:", private_key)
print("Public Key:", public_key)

# Message encoding as a point (for demo)
M = (4726, 3853)  # Pretend message point (on curve)
print("\nMessage Point:", M)

# Encryption
k = random.randint(1, p - 1)
C1 = curve.mult(k, G)
C2 = curve.add(M, curve.mult(k, public_key))
print("\nCiphertext:")
print("C1 =", C1)
print("C2 =", C2)

# Decryption
S = curve.mult(private_key, C1)
S_neg = (S[0], (-S[1]) % p)
M_decrypted = curve.add(C2, S_neg)

print("\nDecrypted Message Point:", M_decrypted)

```
# Output :
<img width="811" height="460" alt="image" src="https://github.com/user-attachments/assets/cf6e38a8-4563-4c93-aeb6-407d8161987e" />

