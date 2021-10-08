
import hashlib
import base64

from enum import Enum
from Crypto.Cipher import AES

class AESKeyLength(Enum):
    KL128 = 128
    KL192 = 192
    KL256 = 256

class AESCipher(object):

    def __init__(self, mode, key_len, key, salt, iv):
        if  isinstance (mode, int) != True:
            raise AttributeError("mode isn't int type")
        if  isinstance (key_len, AESKeyLength) != True:
            raise AttributeError("key_len isn't AESKeyLength type")
        self.mode = mode
        self.key_len = key_len
        self.iv = iv
        self.bs = AES.block_size
        if salt is None:
            self.key = hashlib.sha256(key.encode()).digest()
        else:
            self.key = hashlib.pbkdf2_hmac('sha512', key.encode(), salt.encode(), 1000, int(self.key_len.value / 8))
        if self.mode == AES.MODE_CBC:
            if self.iv is None:
                raise AttributeError("iv is None, should be array for CBC mode")
            iv = hashlib.sha256(self.iv.encode()).digest()[0:16]
            self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        elif self.mode == AES.MODE_ECB:
            self.cipher = AES.new(self.key, AES.MODE_ECB)
        else:
            raise AttributeError("mode is not supported: mode = " + self.mode)

    def encrypt(self, raw):
        raw = self._pad(raw)
        return self.cipher.encrypt(raw.encode())

    def decrypt(self, enc):
        return self._unpad(self.cipher.decrypt(enc))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
