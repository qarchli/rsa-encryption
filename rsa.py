from collections import namedtuple
import sympy  # prime numbers manipulation
import random  # random integers generation

PUBLIC_KEY = namedtuple('Public_Key', ('enc_exponent', 'modulus'))
PRIVATE_KEY = namedtuple('Private_Key', ('dec_exponent', 'modulus'))


class Repository:
    """
    Public keys repository.
    """

    def __init__(self):
        self.public_keys = {}

    def add_key(self, name, key):
        """
        Adds a public key associated with a name to the repository.
        ---
        Args:
            - name(string): name of the key holder.
            - key(namedtuple): public key following the namedtuple convention above.
        Returns:
            - True if all goes well.
        """
        self.public_keys[name] = key

    def get_key(self, name):
        """
                Returns the public key from the holder's name.
                ---
                Args:
                        - name(String): key holder.
                Returns:
                        - public_key(NamedTuple): public key of the specified holder if it exists.
        """
        try:
            return self.public_keys[name]
        except Exception:
            print('Non-existing key. Check the key holder\'s name.')

    def get_all_keys(self):
        """
        Prints all existing keys.
        """
        for name in self.public_keys.keys():
            print(name + ': ', self.get_key(name))


class RSAInstance:
    """
    The RSA instance holding two keys: a public and a private key.
    It can send and receive messages from another RSA instance.
    """

    def __init__(self, name):
        self.name = name
        self.public_key = None
        self.private_key = None

        self._generate_keys()

    def _generate_keys(self):
        """
        function to generate the public and private key
        for the current instance.
        """
        # generate two prime numbers p and q in the interval [Lower, Upper]
        LOWER_BOUND = 0
        UPPER_BOUND = 10e2

        p = sympy.randprime(LOWER_BOUND, UPPER_BOUND)

        # generate q that is different from p
        q = p
        while q == p:
            q = sympy.randprime(LOWER_BOUND, UPPER_BOUND)

        # check whether p and q are both primes and are different numbers
        assert sympy.isprime(p)
        assert sympy.isprime(q)
        assert p != q

        # computing the modulus
        modulus = p * q

        # computing the totient of the modulus
        totient = (p - 1) * (q - 1)

        # selecting the encryption exponent in the interval ]1, totient[
        enc_exponent = 0
        while sympy.gcd(enc_exponent, totient) != 1:
            enc_exponent = random.randrange(2, totient)

        # create public key
        self.public_key = PUBLIC_KEY(enc_exponent, modulus)

        # decryption exponent
        dec_exponent = sympy.mod_inverse(enc_exponent, totient)

        # create private key
        self.private_key = PRIVATE_KEY(dec_exponent, modulus)

        # self.public_key = public_key(947, 8383)
        # self.private_key = private_key(7083, 8383)

    def encrypt(self, msg, to):
        """
        encrypting a message before sending it to another RSA instance.
        ---
        Args:
            - msg(String): message to be sent - Plaintext.
            - to(RSAInstance): receiver.
        Returns:
                - cipher(String): ciphered plaintext.
        """
        ascii_ = ""
        cipher = ""

        # convert string msg to ascii
        for character in msg:
            ascii_ += str(ord(character)) + " "

        # encrypt using public key of the receiver.
        for character in ascii_.strip().split(' '):
            cipher += str((int(character)**to.public_key.enc_exponent) %
                          to.public_key.modulus) + ' '

        return cipher

    def decrypt(self, cipher, from_, dig_sign=False):
        """
        decrypting a message encrypted by another RSA instance.
        ---
        Args:
            - msg(String): message to be sent - Plaintext.
            - to(RSAInstance): receiver.
        Returns:
            - cipher(String): ciphered plaintext.
        """
        # if dig_sign is true => decrypt using public key of from_
        ascii_ = ""
        res = ""

        # decryption using own private key
        for character in cipher.strip().split(' '):
            ascii_ += str((int(character)**self.private_key.dec_exponent) %
                          self.private_key.modulus) + ' '

        # convert ascii to char
        for character in ascii_.strip().split(' '):
            res += chr(int(character))

        return res
