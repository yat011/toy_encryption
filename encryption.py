import base64
import hashlib
from Crypto import Random
import Crypto
from Crypto.Cipher import AES
import argparse
import base64
from getpass import getpass
class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = key

    def encrypt(self, raw):
        pad_key = self._pad(self.key)
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(pad_key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode())).decode('utf-8')

    def decrypt(self, enc):
        pad_key = self._pad(self.key)
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(pad_key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("encrypt", type=int)
    args = parser.parse_args()

    key = getpass("Key:")
    body = getpass("Body:")
    args.key = key
    args.body = body

    aes_obj = AESCipher(args.key)
    if args.encrypt:
        print("Input")
        # print(args.body)
        splits = args.body.split()
        print("Len", len(splits))
        assert len(splits) == 24
        print("Output")
        print(aes_obj.encrypt(args.body))
    else:
        print("Output")
        print(aes_obj.decrypt(args.body))

