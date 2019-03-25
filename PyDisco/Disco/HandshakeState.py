from Asymmetric import Asymmetric
from Tokens import Tokens
from SymmetricState import SymmetricState
from KeyPair import KeyPair
from typing import Tuple
from Strobe import Strobe
from typing import List

class HandshakeState(object):
    symmetric_state : SymmetricState
    key_pair : KeyPair 
    s : KeyPair 
    e : KeyPair 
    rs : KeyPair 
    re : KeyPair 
    initiator : bool = False
    message_patterns : List[List[Tokens]] = []
    should_write : bool = False
    psk : bytes

    def __del__(self) -> None:
        self.s.__del__()
        self.rs.__del__()
        self.e.__del__()
        self.re.__del__()

    def write_message(self, payload : bytes, message_buffer : bytes) -> Tuple[Strobe, Strobe]:
        message_buffer = bytes()

        # is it our turn to write?
        if not self.should_write:
            raise Exception("disco: unexpected call to write_message should be read_message")

        # do we have a token to process?
        if len(self.message_patterns) == 0 or len(self.message_patterns[0]) == 0:
            raise Exception("disco: no more tokens or message patterns to write")

        # process the patterns
        for pattern in self.message_patterns:
            if pattern == Tokens.TOKEN_E:
                self.e = Asymmetric.generate_key_pair()
                message_buffer += bytearray(self.e.public_key)
                self.symmetric_state.mix_hash(bytearray(self.e.public_key))

                if len(self.psk) > 0:
                    self.symmetric_state.mix_key(self.e.public_key)
            elif pattern == Tokens.TOKEN_S:
                encrypted = self.symmetric_state.encrypt_and_hash(bytearray(self.s.public_key))
                message_buffer += encrypted                
            elif pattern == Tokens.TOKEN_EE:
                self.symmetric_state.mix_key(Asymmetric.dh(self.e, self.re.public_key))
            elif pattern == Tokens.TOKEN_ES:
                if self.initiator:
                    self.symmetric_state.mix_key(Asymmetric.dh(self.e, self.rs.public_key))
                else:
                    self.symmetric_state.mix_key(Asymmetric.dh(self.s, self.re.public_key))
            elif pattern == Tokens.TOKEN_SE:
                if self.initiator:
                    self.symmetric_state.mix_key(Asymmetric.dh(self.s, self.re.public_key))
                else:
                    self.symmetric_state.mix_key(Asymmetric.dh(self.e, self.rs.public_key))
            elif pattern == Tokens.TOKEN_SS:
                self.symmetric_state.mix_key(Asymmetric.dh(self.s, self.rs.public_key))
            elif pattern == Tokens.TOKEN_PSK:
                self.symmetric_state.mix_hash(self.psk)
            else:
                raise Exception("Disco: token not recognized")
                
        
        # Appends EncryptAndHash(payload) to the buffer
        ciphertext = self.symmetric_state.encrypt_and_hash(payload)
        message_buffer += ciphertext

        # are there more message patterns to process?
        if len(self.message_patterns) == 1:
            self.message_patterns = []
            # If there are no more message patterns returns two new CipherState objects
            initiator_state, responder_state = self.symmetric_state.split()
        else:
            # remove the pattern from the messagePattern
            self.message_patterns = self.message_patterns[1:]

        # change the direction
        self.should_write = False

        return initiator_state, responder_state

    def read_message(self, message : bytes, payload_buffer : bytes) -> Tuple[Strobe, Strobe]:
        initiator_state : Strobe
        responder_state : Strobe
        payload_buffer = bytes()

        # is it our turn to read?
        if self.should_write:
            raise Exception("disco: unexpected call to ReadMessage should be WriteMessage")

        # do we have a token to process?
        if len(self.message_patterns) == 0 or len(self.message_patterns[0]) == 0:
            raise Exception("disco: no more tokens or message patterns to write")

        # process the patterns
        offset  = 0
        for pattern in self.message_patterns[0]:
            if pattern == Tokens.TOKEN_E:
                if len(message) - offset < Asymmetric.DH_LEN :
                    raise Exception("disco: the received ephemeral key is to short")
                self.re = KeyPair()
                self.re.public_key = message[offset: Asymmetric.DH_LEN]
                offset += Asymmetric.DH_LEN
                self.symmetric_state.mix_hash(self.re.public_key)
                if len(self.psk) > 0:
                    self.symmetric_state.mix_key(self.re.public_key)
            elif pattern == Tokens.TOKEN_S:
                # TODO other tokens here
                pass
        return None, None
