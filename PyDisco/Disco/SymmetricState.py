from Strobe import Strobe
from Symmetric import Symmetric
from typing import Tuple

class SymmetricState(object):

    def __init__(self, protocol_name : str):
        self.strobe_state = Strobe(protocol_name, security=Symmetric.SECURITY_PARAMETER)
        self.is_keyed = False

    def mix_key(self, input_key_material : bytes) -> None:
        self.strobe_state.ad(input_key_material)
        self.is_keyed = True

    def mix_hash(self, data : bytes) -> None:
        self.strobe_state.ad(data) 

    def mix_key_and_hash(self, input_key_material : bytes) -> None:
        self.strobe_state.ad(input_key_material)

    def get_handshake_hash(self) -> bytes:
        return self.strobe_state.prf(Symmetric.HASH_SIZE)

    def encrypt_and_hash(self, plaintext : bytes) -> bytes:
        if not self.is_keyed:
            # no keys, so we don't encrypt
            return plaintext
        ciphertext = self.strobe_state.send_enc(plaintext)
        ciphertext += self.strobe_state.send_mac(Symmetric.TAG_SIZE)
        return ciphertext

    def decrypt_and_hash(self, ciphertext : bytes) -> bytes:
        if not self.is_keyed:
            # no keys, nothing to decypt
            return ciphertext
        
        if len(ciphertext) < Symmetric.TAG_SIZE:
            raise Exception(f'disco: the received payload is shorter then {Symmetric.TAG_SIZE} bytes')
        
        plaintext_len = len(ciphertext) - Symmetric.TAG_SIZE
        plaintext = self.strobe_state.recv_enc(ciphertext[:plaintext_len])

        self.strobe_state.recv_mac(ciphertext[-Symmetric.TAG_SIZE])

        return plaintext

    def split(self) -> Tuple[Strobe, Strobe]:
        initiator_state = self.strobe_state.copy()
        initiator_state.ad(bytearray("initiator", "ASCII"))
        initiator_state.ratchet(Symmetric.HASH_SIZE)

        responderState = self.strobe_state
        responderState.ad(bytearray("responder", "ASCII"))
        responderState.ratchet(Symmetric.HASH_SIZE)

        return initiator_state, responderState

        