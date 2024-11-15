import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from enum import Enum
from math import log2, ceil
from cryptography.hazmat.backends import default_backend
import secrets

prime_rounds = 32
size = 5000


class MersenneTwister:
    def __init__(self, seed=None, w=32):
        global size
        self.w = w
        self.n = size
        self.m = 397
        self.r = 31
        self.a = 2567483615
        self.u = 11
        self.d = (1 << w) - 1
        self.s = 7
        self.b = (1 << w - self.s) - 1
        self.t = 15
        self.c = (1 << self.s) - 1
        self.l = w - 1
        self.f = 1812433253

        if seed is None:
            seed = secrets.randbits(1024)

        self.state = [0] * self.n
        self.state[0] = seed
        for i in range(1, self.n):
            self.state[i] = (self.f * (self.state[i - 1] ^ (self.state[i - 1] >> (self.w - 2))) + i) & self.d

        self.index = self.n

    def extract_number(self):
        if self.index >= self.n:
            self._twist()

        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1
        return y & self.d

    def _twist(self):
        for i in range(self.n):
            x = (self.state[i] & (1 << self.w - 1)) + (self.state[(i + 1) % self.n] & (1 << self.w - 2))
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ xA
        self.index = 0


class Key(Enum):
    PUBLIC = 1
    PRIVATE = 2


class Modmath:
    m: int
    R: int
    mm: int
    R2m: int
    invR: int

    def __init__(self, mod: int):
        self.m = mod
        self.R = 2 ** ceil(log2(mod))
        self.mm = self.R - (self.modinv(mod, self.R))
        self.R2m = (self.R ** 2) % mod
        self.invR = self.modinv(self.R, mod)

    @classmethod
    def modinv(cls, a, n):
        def extended_euclidean(a, b):
            x, y = 0, 1
            last_x, last_y = 1, 0

            while b != 0:
                q, r = divmod(a, b)
                a, b = b, r
                x, last_x = last_x - q * x, x
                y, last_y = last_y - q * y, y

            return a, last_x, last_y

        g, x, y = extended_euclidean(a, n)
        if g != 1:
            raise ValueError('No modular inverse exists')
        return x % n

    @classmethod
    def mod_exp(cls, x, k, mont):
        r = 1
        kl = [int(x) for x in bin(k)[2:]]
        i = 0
        for e in kl:
            r = mont.mod_red(r ** 2)
            if e == 1:
                r = mont.mod_red(r * x)
        i += 1
        return r

    def mod_red(self, x) -> int:
        qm = (x % self.R) * (self.mm % self.R) % self.R
        ym = ((x + (qm * self.m)) // self.R)
        if ym < self.m:
            y = ym
        else:
            y = ym - self.m
        return self._convert(y)

    def _convert(self, u):
        z = u * self.R2m
        return (z * self.invR) % self.m


class RSAcrypt:
    pem: str
    e: int
    n: int
    d: int
    k: int
    mont: Modmath
    keysize: int
    mt: MersenneTwister

    def __init__(self, n, e=0, d=0):
        if e == 0 and d == 0:
            raise ValueError('Invalid input, e and d must not both be null')
        if d == 0:
            self.k = (n.bit_length() + 7) // 8
            self.e = e
        elif e == 0:
            self.k = (n.bit_length() + 7) // 8
            self.d = d
        else:
            self.k = (n.bit_length() + 7) // 8
            self.e = e
            self.d = d
        self.n = n
        self.mont = Modmath(n)
        self.mt = MersenneTwister()

    def encrypt(self, message):
        if not self.e:
            raise NotImplementedError('Encryption key was not provided')
        mLen = len(message)
        if mLen > self.k - 11:
            raise ValueError("message too long")
        ps = []
        while len(ps) != self.k - mLen - 3:
            new_byte = (self.mt.extract_number() % 256).to_bytes(1, 'big')
            if new_byte[0] == 0x00:
                continue
            ps.append(new_byte)
        ps = b"".join(ps)
        if isinstance(message, str):
            message = message.encode('utf-8')

        em = b'\x00\x02' + ps + b'\x00' + message
        m = int.from_bytes(em, 'big')
        c = Modmath.mod_exp(m, self.e, self.mont)
        encrypted_bytes = c.to_bytes(self.k, 'big')
        encrypted_b64 = base64.b64encode(encrypted_bytes)
        encrypted_b64_str = encrypted_b64.decode('utf-8')
        return encrypted_b64_str

    def decrypt(self, encrypted_b64_str, utf8b=True):
        if not self.d:
            raise NotImplementedError('Decryption key was not provided')

        if self.k < 11:
            raise AssertionError('Decryption error, key length invalid')

        encrypted_b64 = encrypted_b64_str.encode('utf-8')
        encrypted_bytes = base64.b64decode(encrypted_b64)
        if len(encrypted_bytes) != self.k:
            raise AssertionError('Decryption error, message length invalid')

        encrypted = int.from_bytes(encrypted_bytes, 'big')
        msg_int = Modmath.mod_exp(encrypted, self.d, self.mont)

        decrypted = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
        if decrypted[0] != 0x02:
            raise AssertionError('Encrypted message is in an invalid format, Supported: PKCS #1 v1.5')
        i = 2
        while i < len(decrypted) and decrypted[i] != 0x00:
            i += 1

        if i == len(decrypted) or i < 8:
            raise AssertionError('Encrypted message is in an invalid format, Supported: PKCS #1 v1.5')
        if utf8b:
            decrypted_padless = decrypted[i + 1:].decode('utf-8')
        else:
            return decrypted[i + 1:]

        return ''.join(decrypted_padless)


class RSA:
    @classmethod
    def from_pem(cls, key_type: Key, pem: str, reverse=False) -> RSAcrypt:
        if not reverse:
            if key_type == Key.PRIVATE:
                d, e, n = cls.pem_to_rsa_private_key(pem)
                return RSAcrypt(d=d, n=n, e=e)
            elif key_type == Key.PUBLIC:
                e, n = cls.pem_to_rsa_public_key(pem)
                return RSAcrypt(e=e, n=n)
            else:
                raise ValueError('Invalid input, must be key_type must be PRIVATE or PUBLIC in PEM initialization')
        else:
            if key_type == Key.PRIVATE:
                d, e, n = cls.pem_to_rsa_private_key(pem)
                return RSAcrypt(d=e, n=n, e=d)
            elif key_type == Key.PUBLIC:
                d, n = cls.pem_to_rsa_public_key(pem)
                return RSAcrypt(d=d, n=n)
            else:
                raise ValueError('Invalid input, must be key_type must be PRIVATE or PUBLIC in PEM initialization')

    @classmethod
    def from_numbers(cls, n: int, e=0, d=0) -> RSAcrypt:
        return RSAcrypt(d=d, n=n, e=e)

    @classmethod
    def pem_to_rsa_private_key(cls, pem):
        private_key = serialization.load_pem_private_key(
            pem.encode(),
            password=None,
            backend=default_backend()
        )
        d = private_key.private_numbers().d
        pubnum = private_key.public_key().public_numbers()
        e = pubnum.e
        n = pubnum.n

        return d, e, n

    @classmethod
    def pem_to_rsa_public_key(cls, pem):
        public_key = serialization.load_pem_public_key(
            pem.encode(),
            backend=default_backend()
        )
        pubnum = public_key.public_numbers()
        e = pubnum.e
        n = pubnum.n

        return e, n

    @classmethod
    def construct_private_pem(cls, p, q, d, e, n=0):
        if n == 0:
            n = p * q
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = Modmath.modinv(q, p)
        private_key = rsa.RSAPrivateNumbers(p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1,
                                            iqmp=iqmp, public_numbers=rsa.RSAPublicNumbers(e, n)).private_key()
        pemprv = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pemprv.decode('utf-8')

    @classmethod
    def construct_public_pem(cls, e, n):
        public_key = rsa.RSAPublicNumbers(e, n).public_key()
        pempub = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )
        return pempub.decode('utf-8')

    @classmethod
    def keygen(cls, bitlen=512):
        mt = MersenneTwister(w=bitlen)

        def generate_e(phi):
            def generate_prime_int(x):
                mt = MersenneTwister()
                while True:
                    p = ((mt.extract_number() + 2) % x) | 1
                    if is_prime(p):
                        return p

            if 65537 < phi:
                return 65537
            else:
                return generate_prime_int(phi)

        def generate_prime_bits(nbits):
            mt = MersenneTwister(w=bitlen)
            while True:
                p = (mt.extract_number() % (2 ** nbits)) | (1 << (nbits - 1)) | 1
                if is_prime(p):
                    return p

        def is_prime(n, k=prime_rounds):
            mont = Modmath(n)
            if n < 2:
                return False
            if n == 2:
                return True
            if n % 2 == 0:
                return False

            d = n - 1
            r = 0
            while d % 2 == 0:
                r += 1
                d //= 2

            for _ in range(k):
                a = ((mt.extract_number() % (2 ** n.bit_length())) + 2) % (n - 1)
                x = Modmath.mod_exp(a, d, mont)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(r - 1):
                    x = mont.mod_red(x * x)
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        p = generate_prime_bits(bitlen // 2)
        q = generate_prime_bits(bitlen // 2)
        while p == q:
            mt = MersenneTwister(w=bitlen)
            q = generate_prime_bits(bitlen // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = generate_e(phi)
        d = Modmath.modinv(e, phi)
        return p, q, d, e, n, RSA.construct_private_pem(p, q, d, e, n), RSA.construct_public_pem(e, n)
