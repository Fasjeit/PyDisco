from Symmetric import Symmetric
from KeyPair import KeyPair
from NoiseHandshakeType import NoiseHandshakeType

class NoiseConfig(object):    
    DISCO_DRAFT_VERSION : str = "3"
    NOISE_DH : str = "25519"
    NOISE_MESSAGE_LENGTH : int = 65535 - 2 # 2-byte length
    NOISE_TAG_LENGTH : int = Symmetric.TAG_SIZE;
    NOISE_MAX_PLAINTEXT_SIZE : int = NOISE_MESSAGE_LENGTH - NOISE_TAG_LENGTH

    half_duplex : bool
    key_pair : KeyPair 
    pre_shared_key : bytearray  = bytearray()
    prologue : bytes = bytes()
    remote_key : bytes = bytes()
    static_public_key_proof : bytes = bytes()
    handshake_pattern : NoiseHandshakeType
    public_key_verifier = None
    