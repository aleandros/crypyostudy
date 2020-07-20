from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import gmpy2
import os

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()


def simple_rsa_encrypt(m, public_key):
    numbers = public_key.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


def simple_rsa_decrypt(c, private_key):
    numbers = private_key.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

def random_int():
    return int.from_bytes(os.urandom(16), byteorder='big')

# Illustrating the property
m = random_int()
r = 2
n = public_key.public_numbers().n
mr = m * r
c_m = simple_rsa_encrypt(m, public_key)
c_r = simple_rsa_encrypt(r, public_key)
c_mr = (c_m * c_r) % n
d_mr = simple_rsa_decrypt(c_mr, private_key)
assert mr == d_mr

# Simulate an attack: let's say the attacker wants to learn
# the plaintext of c_m, so intercepts the message, multiplies it by c_r, and gets
# the private key owner to decrypt it. 
# It is then posible to recover m, since r is known:
r_inv_modoulo_n = gmpy2.powmod(r, -1, n)
assert (d_mr * r_inv_modoulo_n) % n == m