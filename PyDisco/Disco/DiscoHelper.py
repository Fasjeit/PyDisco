from HandshakePattern import HandshakePattern
from HandshakeState import HandshakeState
from SymmetricState import SymmetricState
from Tokens import Tokens
from KeyPair import KeyPair
from NoiseHandshakeType import NoiseHandshakeType

class DiscoHelper(object):
    
    @staticmethod
    def InitializeDisco(
            handshake_type : NoiseHandshakeType, 
            initiator : bool, 
            prologue : bytes, 
            s : KeyPair = None, 
            e : KeyPair = None, 
            rs : KeyPair = None, 
            re : KeyPair = None) -> HandshakeState:

        handshake_pattern = HandshakePattern.get_pattern(handshake_type)

        handshake_state = HandshakeState()
        handshake_state.symmetric_state = SymmetricState(f'Noise_{handshake_pattern.name}_25519_STROBEv1.0.2')
        handshake_state.initiator = initiator
        handshake_state.should_write = initiator

        try:
            if prologue is not None:
                handshake_state.symmetric_state.mix_hash(prologue)
            if s is not None:
                handshake_state.s = s
            if e is not None:
                raise Exception('disco: fallback patterns are not implemented')
            if rs is not None:
                handshake_state.rs = rs
            if re is not None:
                raise Exception('disco: fallback patterns are not implemented')

            # initiator pre-message pattern
            for token in handshake_pattern.pre_message_patterns[0]:
                if token == Tokens.TOKEN_S:
                    if initiator:
                        if s is None:
                            raise Exception('disco: the static key of the client should be set')
                        handshake_state.symmetric_state.mix_hash(s.public_key)
                    else:
                        if rs is None:
                            raise Exception('disco: the remote static key of the server should be set')
                        handshake_state.symmetric_state.mix_hash(rs.public_key)
                else:
                    raise Exception('disco: token of pre-message not supported')
            
            # responder pre-message pattern
            for token in handshake_pattern.pre_message_patterns[1]:
                if token == Tokens.TOKEN_S:
                    if initiator:
                        if rs is None:
                            raise Exception('disco: the remote static key of the client should be set')
                        handshake_state.symmetric_state.mix_hash(rs.public_key)
                    else:
                        if s is None:
                            raise Exception('disco: the static key of the server should be set')
                        handshake_state.symmetric_state.mix_hash(s.public_key)
                else:
                    raise Exception('disco: token of pre - message not supported')
            handshake_state.message_patterns = handshake_pattern.message_patterns
            return handshake_state

        except Exception as ex:
            handshake_state.__del__()
            raise ex
