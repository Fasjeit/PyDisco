from NoiseHandshakeType import NoiseHandshakeType
from Tokens import Tokens
from typing import List
from typing import Tuple

class HandshakePattern(object):
    # static fileds
    pattern_dictionary : dict = {}
    Noise_N : HandshakePattern
    Noise_NK : HandshakePattern
    Noise_K : HandshakePattern
    Noise_X : HandshakePattern

    name : str
    pre_message_patterns : List[List[Tokens]]
    message_patterns : List[List[Tokens]]

    def __init__(
        self, 
        pattern : NoiseHandshakeType, 
        name : str, 
        pre_message_patterns : List[List[Tokens]], 
        message_patterns : List[List[Tokens]]):
            if HandshakePattern.pattern_dictionary.__contains__(pattern):
                raise Exception("pattern of the same type is already exits!")
            self.name = name
            self.message_patterns = message_patterns
            self.pre_message_patterns = pre_message_patterns
            HandshakePattern.pattern_dictionary[pattern] = self

    @staticmethod
    def __static_init_patterns__() -> None:        
        HandshakePattern.pattern_dictionary = {}

        HandshakePattern.Noise_N = HandshakePattern(
            NoiseHandshakeType.NOISE_NK,
            name = "N",
            pre_message_patterns = 
            [
                [],                # →
                [Tokens.TOKEN_S]   # ←
            ],
            message_patterns = 
            [
                [Tokens.TOKEN_E, Tokens.TOKEN_ES] # →
            ]   
        )

        HandshakePattern.Noise_NK = HandshakePattern(
            NoiseHandshakeType.NOISE_NK,
            name = "NK",
            pre_message_patterns = 
            [
                [],              # →
                [Tokens.TOKEN_S] # ←
            ],
            message_patterns = 
            [
                [Tokens.TOKEN_E, Tokens.TOKEN_ES], # →
                [Tokens.TOKEN_E, Tokens.TOKEN_EE]  # ←
            ]     
        )             
    
    @staticmethod
    def get_pattern(noise_type : NoiseHandshakeType) -> HandshakePattern:
        if HandshakePattern.pattern_dictionary is None:
            HandshakePattern.__static_init_patterns__()
        return HandshakePattern.pattern_dictionary[noise_type]
    
