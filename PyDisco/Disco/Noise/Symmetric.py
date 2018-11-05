"""
Symmetric Disco module
"""
from Strobe.Strobe import Strobe
import os

class Symmetric(object):
    """description of class"""
    SECURITY_PARAMETER = 128
    NONCE_SIZE = 192 // 8
    TAG_SIZE = SECURITY_PARAMETER // 8
    MINIMUM_CIPHERTEXT_SIZE = NONCE_SIZE + TAG_SIZE
    HASH_SIZE = SECURITY_PARAMETER * 2 // 8
    KEY_SIZE = SECURITY_PARAMETER // 8;
    PSK_KEY_SIZE = 32;

    def __init__(self):
        pass

    @staticmethod
    def hash(input, output_len):
        if output_len < Symmetric.HASH_SIZE:
            raise Exception(f'discoNet: an output length smaller than {Symmetric.HASH_SIZE*8}-bit' 
                            + f' ({Symmetric.HASH_SIZE} bytes) has security consequences"')

        hash = Strobe("DiscoHash")
        hash.ad(input)
        return hash.prf(output_len)

    @staticmethod
    def Encrypt(key, plaintext):
        if (len(key) < Symmetric.KEY_SIZE):
            raise Exception(f'disco: using a key smaller than {Symmetric.KEY_SIZE*8}-bit' 
                            + f' ({Symmetric.KEY_SIZE} bytes) has security consequences"')
        ae = Strobe("DiscoAEAD", security = Symmetric.SECURITY_PARAMETER)

        # Absorb the key
        ae.ad(key)

        # Generate 192-bit nonce
        nonce = bytearray(os.urandom(Symmetric.NONCE_SIZE))
        
        # Absorb the nonce
        ae.ad(nonce)

        # nonce + send_ENC(plaintext) + send_MAC(16)
        ct = ae.send_enc(plaintext)
        mac = ae.send_mac(Symmetric.TAG_SIZE)
        ciphertext  = nonce + ct + mac

        return ciphertext
    
    @staticmethod
    def Decrypt(key, ciphertext):
        if (len(key) < Symmetric.KEY_SIZE):
            raise Exception(f'disco: using a key smaller than {Symmetric.KEY_SIZE*8}-bit' 
                            + f' ({Symmetric.KEY_SIZE} bytes) has security consequences')
        
        if len(ciphertext) < Symmetric.MINIMUM_CIPHERTEXT_SIZE:
            raise Exception(f'disco: ciphertext is too small, it should contain at a '
                            + f'minimum a {Symmetric.NonceSize * 8}-bit nonce and a {Symmetric.NonceSize * 8}-bit tag')
        ae = Strobe("DiscoAEAD", security = Symmetric.SECURITY_PARAMETER)

        # Absorb the key
        ae.ad(key)
        
        # Absorb the nonce
        ae.ad(ciphertext[0:Symmetric.NONCE_SIZE])

        plaintext_size = len(ciphertext) - Symmetric.TAG_SIZE - Symmetric.NONCE_SIZE

        # Decrypt
        plaintext = ae.recv_enc(ciphertext[Symmetric.NONCE_SIZE:Symmetric.NONCE_SIZE + plaintext_size]) 

        # Verify tag
        ae.recv_mac(ciphertext[-Symmetric.TAG_SIZE:])

        return plaintext

    @staticmethod
    def ProtectIntegrity(key, plaintext):
        if (len(key) < Symmetric.KEY_SIZE):
                raise Exception(f'disco: using a key smaller than {Symmetric.KEY_SIZE*8}-bit' 
                                + f' ({Symmetric.KEY_SIZE} bytes) has security consequences')
        hash = Strobe("DiscoMAC", security=Symmetric.SECURITY_PARAMETER)
        hash.ad(key)
        hash.ad(plaintext)
        return plaintext + hash.send_mac(Symmetric.TAG_SIZE)

    @staticmethod
    def VerifyIntegrity(key, plaintextAndTag):
        if (len(key) < Symmetric.KEY_SIZE):
                raise Exception(f'disco: using a key smaller than {Symmetric.KEY_SIZE*8}-bit' 
                                + f' ({Symmetric.KEY_SIZE} bytes) has security consequences')
        if (len(plaintextAndTag) < Symmetric.TAG_SIZE):
            raise Exception("disco: plaintext does not contain an integrity tag")

        # Getting the tag        
        plaintext = plaintextAndTag[0:len(plaintextAndTag) - Symmetric.TAG_SIZE]
        hash = Strobe("DiscoMAC", security=Symmetric.SECURITY_PARAMETER)
        hash.ad(key)
        hash.ad(plaintext)

        # Verifying the tag
        hash.recv_mac(plaintextAndTag[-Symmetric.TAG_SIZE:])

        return plaintext         