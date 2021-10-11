
import os
import hashlib

from enum import Enum
from Crypto.Cipher import AES

class AESKeyLength(Enum):
    KL128 = 128
    KL192 = 192
    KL256 = 256

class AESCipher(object):

    def __init__(self, mode, key_len, key, salt):
        if  isinstance (mode, int) != True:
            raise AttributeError("mode isn't int type")
        if  isinstance (key_len, AESKeyLength) != True:
            raise AttributeError("key_len isn't AESKeyLength type")
        self.mode = mode
        self.key_len = key_len
        if salt is None:
            self.key = hashlib.sha256(key.encode()).digest()
        else:
            self.key = hashlib.pbkdf2_hmac('sha512', key.encode(), salt.encode(), 1000, int(self.key_len.value / 8))

    def encrypt(self, raw):
        if self.mode == AES.MODE_CBC:
            iv = os.urandom(16)
            self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
            raw = self._pad(raw)
            enc_raw = self.cipher.encrypt(raw.encode())
            return (iv + enc_raw)
        elif self.mode == AES.MODE_ECB:
            self.cipher = AES.new(self.key, AES.MODE_ECB)
            raw = self._pad(raw)
            return self.cipher.encrypt(raw.encode())
        else:
            raise AttributeError("mode is not supported: mode = " + self.mode)

    def decrypt(self, enc):
        if self.mode == AES.MODE_CBC:
            iv = enc[0:16]
            self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return self._unpad(self.cipher.decrypt(enc[16:]))
        elif self.mode == AES.MODE_ECB:
            self.cipher = AES.new(self.key, AES.MODE_ECB)
            return self._unpad(self.cipher.decrypt(enc))
        else:
            raise AttributeError("mode is not supported: mode = " + self.mode)

    def _pad(self, s):
        bs = AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
