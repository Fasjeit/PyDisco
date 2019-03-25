import os
from Symmetric import Symmetric
from KeyPair import KeyPair
import nacl.utils
from nacl.public import PrivateKey

class Asymmetric(object):
    DH_LEN = 32

    @staticmethod
    def generate_key_pair(private_key : bytes = None) -> KeyPair:
        key_pair = KeyPair()

        if private_key is None:
            key_pair.private_key = bytes(os.urandom(Asymmetric.DH_LEN))
        else:
            if len(private_key) != Asymmetric.DH_LEN:
                raise Exception(f'disco: expecting {Asymmetric.DH_LEN} byte key array')
            key_pair.private_key = private_key

        key_pair.public_key = nacl.bindings.crypto_scalarmult_base(key_pair.private_key)
        
        #kp = PrivateKey(bytes(key_pair.private_key))
        #key_pair.public_key = bytearray(kp.public_key._public_key)
        return key_pair
    
    @staticmethod
    def dh(key_pair : KeyPair, public_key : bytes) -> bytes:
        return nacl.bindings.crypto_scalarmult(key_pair.private_key, public_key)

if __name__ == "__main__":
    print("qwe")
    a = Asymmetric.generate_key_pair()
    b = Asymmetric.dh(a, a.public_key)
    print("qwe-end")