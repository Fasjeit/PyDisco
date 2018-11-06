from Asymmetric import Asymmetric
from Tokens import Tokens

class HandshakeState(object):
    symmetric_state = None
    key_pair = None
    s = None
    e = None
    rs = None
    re = None
    initiator = False
    message_patterns = []
    should_write = False
    psk = None

    def __del__(self):
        self.s.__del__()
        self.rs.__del__()
        self.e.__del__()
        self.re.__del__()

    def write_message(self, payload, message_buffer):
        message_buffer = []

        # is it our turn to write?
        if not self.should_write:
            raise Exception("disco: unexpected call to write_message should be read_message")

        # do we have a token to process?
        if len(self.message_patterns) == 0 or len(self.message_patterns[0].tokens) == 0:
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
            self.message_patterns = None
            # If there are no more message patterns returns two new CipherState objects
            initiator_state, responder_state = self.symmetric_state.split()
        else:
            # remove the pattern from the messagePattern
            self.message_patterns = self.message_patterns[1:]

        # change the direction
        self.should_write = False

        return initiator_state, responder_state

