from abc import ABC, abstractmethod
from Crypto.Cipher import AES
from pygost.gost3412 import GOST3412Kuznechik
from twofish import Twofish
from pyserpent import Serpent
import camellia


class Abstract_cypher(ABC):
    @abstractmethod
    def encrypt(self, message, key):
        pass

    @abstractmethod
    def decrypt(self, message, key):
        pass

    @abstractmethod
    def cyp_name(self):
        pass


class NoEncrypt(Abstract_cypher):

    def encrypt(self, message, key):
        return message

    def decrypt(self, message, key):
        return message

    def cyp_name(self):
        return ''


class Encryption_interface(Abstract_cypher):
    _encryption: Abstract_cypher = None

    def __init__(self, enc: Abstract_cypher = None) -> None:
        self._encryption = enc

    @property
    def encryption(self):
        return self._encryption

    def encrypt(self, message, key):
        return self._encryption.encrypt(message, key)

    def decrypt(self, message, key):
        return self._encryption.decrypt(message, key)

    def cyp_name(self):
        return self._encryption.cyp_name()


class AES_cypher(Encryption_interface):

    def encrypt(self, message, key):
        cipher = AES.new(key, AES.MODE_EAX)
        data = cipher.encrypt(message)
        return self.encryption.encrypt(data, key)

    def decrypt(self, message, key):
        cipher = AES.new(key, AES.MODE_EAX)
        plaintext = cipher.decrypt(message)
        return plaintext

    def cyp_name(self):
        return "Encryption AES  " + self._encryption.cyp_name()


class SERPENT_cypher(Encryption_interface):

    def encrypt(self, message, key):
        data = Serpent(key).encrypt(message)
        return self.encryption.encrypt(data, key)

    def decrypt(self, message, key):
        data = Serpent(key).decrypt(message)
        return data

    def cyp_name(self):
        return "Encryption SERPENT " + self.encryption.cyp_name()


class TWOFISH_cipher(Encryption_interface):

    def encrypt(self, message, key):
        cipher = Twofish(key)
        data = b''
        for i in range(0, len(message), 16):
            st = message[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            data += cipher.encrypt(st)
        return self.encryption.encrypt(data, key)

    def decrypt(self, message, key):
        cipher = Twofish(key)
        data = b''
        for i in range(0, len(message), 16):
            st = message[i:i + 16]
            data += cipher.decrypt(st)
        return data

    def cyp_name(self):
        return "Encryption TWOFISH " + self.encryption.cyp_name()


class CAMELLIA_cipher(Encryption_interface):

    def encrypt(self, message, key):
        cipher = camellia.CamelliaCipher(key=key, IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
        data = cipher.encrypt(message)
        return self.encryption.encrypt(data, key)

    def decrypt(self, message, key):
        cipher = camellia.CamelliaCipher(key=key, IV=b'16 byte iv. abcd', mode=camellia.MODE_CBC)
        data = cipher.decrypt(message)
        return data

    def cyp_name(self):
        return "Encryption CAMELLIA" + self.encryption.cyp_name()


class KUZNECHIK_cipher(Encryption_interface):

    def encrypt(self, message, key):
        cipher = GOST3412Kuznechik(key)
        data = b''
        for i in range(0, len(message), 16):
            st = message[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            data += cipher.encrypt(st)
        return self.encryption.encrypt(data, key)

    def decrypt(self, message, key):
        cipher = GOST3412Kuznechik(key)
        data = b''
        for i in range(0, len(message), 16):
            st = message[i:i + 16]
            if len(st) < 16:
                st = st + b' ' * (16 - len(st))
            data += cipher.decrypt(st)
        return data

    def cyp_name(self):
        return "Encryption KUZNECHIK " + self.encryption.cyp_name()
