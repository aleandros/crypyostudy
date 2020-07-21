from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import gmpy2
from collections import namedtuple
from dataclasses import dataclass
from typing import Any

Interval = namedtuple("Interval", ["a", "b"])


def simple_rsa_decrypt(c, private_key):
    numbers = private_key.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)


def simple_rsa_encrypt(m, public_key):
    numbers = public_key.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


def int_to_bytes(i, min_size=None):
    i = int(i)
    b = i.to_bytes((i.bit_length() + 7) // 8, byteorder="big")
    if min_size is not None and len(b) < min_size:
        b = b"\x00" * (min_size - len(b)) + b
    return b


def bytes_to_int(b):
    return int.from_bytes(b, byteorder="big")


@dataclass
class FakeOracle:
    private_key: Any

    def __call__(self, ciphertext: bytes) -> bool:
        recovered_as_int = simple_rsa_decrypt(ciphertext, self.private_key)
        recovered = int_to_bytes(recovered_as_int, self.private_key.key_size // 8)
        return recovered[0:2] == bytes([0, 2])


@dataclass
class RSAOracleAttacker:
    public_key: Any
    oracle: FakeOracle

    def _step1_binding(self, c):
        self.c0 = c
        self.B = 2 ** (self.public_key.key_size - 16)
        self.s = [1]
        self.M = [[Interval(2 * self.B, (3 * self.B) - 1)]]
        self.i = 1
        self.n = self.public_key.public_numbers().n

    def _find_s(self, start_s, s_max=None):
        si = start_s
        ci = simple_rsa_encrypt(si, self.public_key)

        while not self.oracle((self.c0 * ci) % self.n):
            si += 1
            if s_max and (si > s_max):
                return None
            ci = simple_rsa_encrypt(si, self.public_key)

        return si

    def _step2a_start_the_searching(self):
        si = self._find_s(start_s=gmpy2.c_div(self.n, 3 * self.B))
        return si

    def _step2b_searching_with_more_than_one_interval(self):
        si = self._find_s(start_s=self.s[-1] + 1)
        return si

    def _step2c_searching_with_one_interval_left(self):
        a, b = self.M[-1][0]
        ri = gmpy2.c_div(2 * (b * self.s[-1] - 2 * self.B), self.n)
        si = None

        while si is None:
            si = gmpy2.c_div((2 * self.B + ri * self.n), b)
            s_max = gmpy2.c_div((3 * self.B + ri * self.n), a)
            si = self._find_s(start_s=si, s_max=s_max)
            ri += 1

        return si

    def _step3_narrowing_set_of_solutions(self, si):
        new_intervals = set()
        for a, b in self.M[-1]:
            r_min = gmpy2.c_div((a * si - 3 * self.B + 1), self.n)
            r_max = gmpy2.f_div((b * si - 2 * self.B), self.n)

            for r in range(r_min, r_max + 1):
                a_candidate = gmpy2.c_div((2 * self.B + r * self.n), si)
                b_candidate = gmpy2.f_div((3 * self.B - 1 + r * self.n), si)

                new_interval = Interval(max(a, a_candidate), min(b, b_candidate))
                new_intervals.add(new_interval)

        new_intervals = list(new_intervals)
        self.M.append(new_intervals)
        self.s.append(si)

        if len(new_intervals) == 1 and new_intervals[0].a == new_intervals[0].b:
            return True
        return False

    def _step4_computing_the_solution(self):
        interval = self.M[-1][0]
        return interval.a

    def attack(self, c):
        self._step1_binding(c)

        finished = False
        si = None
        while not finished:
            if self.i == 1:
                si = self._step2a_start_the_searching()
            elif len(self.M[-1]) > 1:
                si = self._step2b_searching_with_more_than_one_interval()
            elif len(self.M[-1]) == 1:
                si = self._step2c_searching_with_one_interval_left()

            finished = self._step3_narrowing_set_of_solutions(si)
            self.i += 1
        m = self._step4_computing_the_solution()
        return m


# keysize should be 2048, but 512 is used for speed (in terms of testing the attack)
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=512, backend=default_backend()
)

public_key = private_key.public_key()


message = b"test"

ciphertext = public_key.encrypt(message, padding.PKCS1v15())
ciphertext_as_int = bytes_to_int(ciphertext)
oracle = FakeOracle(private_key)
attacker = RSAOracleAttacker(public_key, oracle)
recovered = int_to_bytes(attacker.attack(ciphertext_as_int))

print(f"Plaintext: {message}")
print(f"Recovered: {recovered}")
