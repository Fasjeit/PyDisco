from NoiseConfig import NoiseConfig
from threading import Lock
from Strobe import Strobe
from HandshakePattern import HandshakePattern
from HandshakeState import HandshakeState
from KeyPair import KeyPair
from Asymmetric import Asymmetric
from DiscoHelper import DiscoHelper
from socket import socket

class Connection(object):
    _config : NoiseConfig
    _half_duplex_mutex : Lock = Lock()
    _handshake_mutex : Lock = Lock()
    _in_lock : Lock = Lock()
    _out_lock : Lock = Lock()
    _isClient : bool
    _connection : socket
    _handshake_complite : bool
    _input_buffer : bytes
    _is_half_duplex : bool
    _is_remote_authenticated : bool
    _strobe_in : Strobe
    _strobe_out : Strobe
    RemotePublicKey : bytes

    @staticmethod
    def validate_parameters(buffer: bytes, offset: int, count: int) -> None:
        if buffer is None:
            raise Exception('buffer should be set')
        if offset < 0:
            raise Exception('offset should be positive integer')
        if count < 0:
            raise Exception('count should be positive integer')
        if (count > len(buffer) - offset):
            raise Exception(f'Not enough bytes in buffer to process, expecting at least {count + offset}')

    def __init__(self, connection: socket):
        self._connection = connection


    def write(self, data: bytes, offset: int, count: int) -> int:
        Connection.validate_parameters(data, offset, count)

        # If this is a one-way pattern, do some checks
        handshakePattern = self._config.handshake_pattern
        if not self._isClient and (handshakePattern == HandshakePattern.Noise_N or handshakePattern == HandshakePattern.Noise_K or handshakePattern == HandshakePattern.Noise_X):
            raise Exception('disco: a server should not write on one-way patterns')

        # Make sure to go through the handshake first
        return 0

    def handshake(self) -> None:
        # Locking the handshakeMutex
        self._handshake_mutex.acquire()
        handshake_state : HandshakeState

        try:
            c1 : Strobe
            c2 : Strobe
            received_payload : bytes
            
            # did we already go through the handshake?
            if (self._handshake_complite):
                return

            remoteKeyPair : KeyPair
            if self._config.remote_key is not None:
                if len(self._config.remote_key) != Asymmetric.DH_LEN:
                    raise Exception(f'disco: the provided remote key is not {Asymmetric.DH_LEN}-byte')


                remoteKeyPair = KeyPair()
                remoteKeyPair.public_key = self._config.remote_key[:]

            handshake_state = DiscoHelper.InitializeDisco(
                self._config.handshake_pattern, 
                self._isClient, 
                self._config.prologue, 
                self._config.key_pair, 
                None, 
                remoteKeyPair, 
                None)

            handshake_state.psk = self._config.pre_shared_key

            # toDo copy code from golang impl
            while(True):
                # start handshake
                if handshake_state.should_write:
                    buf_to_write : bytes = bytes()
                    proof : bytes
                    if len(handshake_state.message_patterns) <= 2:
                        proof = self._config.static_public_key_proof
                    else:
                        proof = bytes()
                    c1,c2 = handshake_state.write_message(proof, buf_to_write)

                    # header (lenght)
                    length_bytes = bytes([len(buf_to_write)>>8, (len(buf_to_write) % 256)])
                    self._connection.send(length_bytes + buf_to_write)
                else:
                    buf_header = self._connection.recv(2)
                    length = (buf_header[0] << 8) | buf_header[1]
                    if (length > self._config.NOISE_MESSAGE_LENGTH):
                        raise Exception("disco: Disco message received exceeds DiscoMessageLength")
                    noise_message = self._connection.recv(length)
                    c1,c1 = handshake_state.read_message(noise_message, received_payload)
                if c1 is None:
                    break
                # Has the other peer been authenticated so far?
                if not self._is_remote_authenticated and self._config.public_key_verifier is not None:
                    is_remote_static_key_set = 0
                    # test if remote static key is empty
                    for val in handshake_state.rs.public_key:
                        is_remote_static_key_set = is_remote_static_key_set | val
                    if (is_remote_static_key_set != 0):
                        # a remote static key has been received. Verify it
                        if not self._config.public_key_verifier(handshake_state.rs.public_key, received_payload):
                            raise Exception("disco: the received public key could not be authenticated")
                        self._is_remote_authenticated = True
                        self.remote_public_key = handshake_state.rs.public_key
                # Processing the final handshake message returns two CipherState objects
                # the first for encrypting transport messages from initiator to responder
                # and the second for messages in the other direction.
                if c2 is not None:
                    if self._isClient:
                        self._strobe_out, self._strobe_in = c1, c2
                    else:
                        self._strobe_out, self._strobe_in = c1, c2
                else:
                    self._is_half_duplex = True
                    self._strobe_in = c1
                    self._strobe_out = c1
        finally:
            handshake_state.__del__()
            # no errors :)
            self._handshake_mutex.release()