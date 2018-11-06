from enum import Enum

class NoiseHandshakeType(Enum):
    UNKNOWN = 0
    NOISE_N = 1
    NOISE_K = 2
    NOISE_X = 3
    NOISE_KK = 4
    NOISE_NX = 5
    NOISE_NK = 6
    NOISE_XX = 7
    NOISE_KX = 8
    NOISE_XK = 9
    NOISE_IK = 10
    NOISE_IX = 11
    NOISE_NN_PSK2 = 12
    NOISE_NN = 13
    NOISE_KN = 14
    NOISE_XN = 15
    NOISE_IN = 16