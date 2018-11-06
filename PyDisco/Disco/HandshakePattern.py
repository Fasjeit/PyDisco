from NoiseHandshakeType import NoiseHandshakeType
from Tokens import Tokens

class HandshakePattern(object):
    pattern_dictionary = None

    def __init__(self, pattern, name, pre_message_patterns, message_patterns):
        if HandshakePattern.pattern_dictionary.__contains__(pattern):
            raise Exception("pattern of the same type is already exits!")
        self.name = name
        self.message_patterns = message_patterns
        self.pre_message_patterns = pre_message_patterns
        HandshakePattern.pattern_dictionary[pattern] = self

    @staticmethod
    def __static_init_patterns__():        
        HandshakePattern.pattern_dictionary = {}

        HandshakePattern.Noise_N = HandshakePattern(
            NoiseHandshakeType.NOISE_NK,
            name = "N",
            pre_message_patterns = 
            [
                [], # →
                [Tokens.TOKEN_S]# ←
            ],
            message_patterns = 
            [
                [Tokens.TOKEN_E, Tokens.TOKEN_ES] # →
            ]   
        )

        HandshakePattern.Noise_NK = HandshakePattern(
            NoiseHandshakeType.NOISE_NK,
            name = "N",
            pre_message_patterns = 
            [
                [], # →
                [Tokens.TOKEN_S]# ←
            ],
            message_patterns = 
            [
                [Tokens.TOKEN_E, Tokens.TOKEN_ES] # →,
                [Tokens.TOKEN_E, Tokens.TOKEN_EE] # ←
            ]     
        )             
    
    @staticmethod
    def get_pattern(noise_type):
        if HandshakePattern.pattern_dictionary is None:
            HandshakePattern.__static_init_patterns__()
        return HandshakePattern.pattern_dictionary[noise_type]
    
