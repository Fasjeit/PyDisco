from NoiseConfig import NoiseConfig
from threading import Lock
from Strobe import Strobe
from HandshakePattern import HandshakePatterns
from HandshakeState import HandshakeState
from KeyPair import KeyPair
from Asymmetric import Asymmetric
from DiscoHelper import DiscoHelper
from socket import socket
from Symmetric import Symmetric
from NoiseHandshakeType import NoiseHandshakeType

class Connection(object):
    _config : NoiseConfig
    _half_duplex_mutex : Lock 
    _handshake_mutex : Lock 
    _in_lock : Lock 
    _out_lock : Lock 
    _is_client : bool
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
        self._handshake_mutex = Lock()
        self._half_duplex_mutex = Lock()
        self._in_lock = Lock()
        self._out_lock = Lock()
        self._handshake_complite = False
        self._is_remote_authenticated = False
        self._is_client = False
        self._is_half_duplex = False
        self._input_buffer = bytes()


    def write(self, data: bytes, offset: int, count: int) -> int:
        Connection.validate_parameters(data, offset, count)

        # If this is a one-way pattern, do some checks
        handshakePattern = self._config.handshake_pattern
        if not self._isClient and (handshakePattern == HandshakePatterns.Noise_N or handshakePattern == HandshakePatterns.Noise_K or handshakePattern == HandshakePatterns.Noise_X):
            raise Exception('disco: a server should not write on one-way patterns')

        # Make sure to go through the handshake first
        self.handshake()

        mutex : Lock

        # Lock the write mutex
        if self._is_half_duplex:
            mutex = self._half_duplex_mutex
        else:
            mutex = self._out_lock
        mutex.acquire()
        try:
            total_bytes = 0

            # process the data in loop
            while count - total_bytes > 0:
                data_len = NoiseConfig.NOISE_MAX_PLAINTEXT_SIZE if count > NoiseConfig.NOISE_MAX_PLAINTEXT_SIZE else count 
                data_len = count - total_bytes if data_len > count - total_bytes else data_len
            
                # encrypt
                ciphertext = self._strobe_out.send_enc(data[offset: offset + data_len])
                mac = self._strobe_out.send_mac(Symmetric.TAG_SIZE)

                total_length = len(ciphertext) + len (mac)
                length = bytearray([(total_length)>>8, ((total_length) % 256)])
                # send data
                # len || ct|| mac

                self._connection.send(length)
                self._connection.send(ciphertext)
                self._connection.send(mac)

                # prepare next loop iteration
                total_bytes += data_len
                offset += data_len
            return total_bytes
        finally:
            mutex.release()

    def read_from_until(self, count : int):
        buf = b''
        while count:
            newbuf = self._connection.recv(count)
            #Q_ ?????
            #if not newbuf: return None
            buf += newbuf
            count -= len(newbuf)
        return buf

    def read(self, data: bytes, offset: int, count: int) -> int:
        if data == None or len(data) == 0:
            return 0
        
        Connection.validate_parameters(data, offset, count)
        
        # Make sure to go through the handshake first
        self.handshake()

        # If this is a one-way pattern, do some checks
        ht = self._config.handshake_pattern
        if (self._is_client 
            and (ht == NoiseHandshakeType.NOISE_N 
            or ht == NoiseHandshakeType.NOISE_K 
            or NoiseHandshakeType.NOISE_X)):
                raise Exception('disco: a client should not read on one - way patterns')
        
        # Lock the read socket
        mutex : Lock
        if self._is_half_duplex:
            mutex = self._half_duplex_mutex
        else:
            mutex = self._in_lock
        mutex.acquire()

        try:
            # read whatever there is to read in the buffer
            if len(self._input_buffer) > 0:
                to_read = count if len(self._input_buffer) > count else len(self._input_buffer)
                data = self._input_buffer[:to_read]
                if len(self._input_buffer) > count:
                    self._input_buffer[:to_read]
                    return count
                self._input_buffer = bytes()
                return to_read
            # read header from socket
            buf_header = self.read_from_until(2)
            length = (buf_header[0] << 8) | buf_header[1]
            if (length > self._config.NOISE_MESSAGE_LENGTH):
                raise Exception("disco: Disco message received exceeds DiscoMessageLength")

            # read noise message from socket    
            noise_message = self.read_from_until(length)

            # decrypt
            if length < Symmetric.TAG_SIZE:
                raise Exception(f'disco: the received payload is shorter {Symmetric.TAG_SIZE} bytes')
            
            plaintext = self._strobe_in.recv_enc(noise_message[:length - Symmetric.TAG_SIZE])
            try:
                self._strobe_in.recv_mac(noise_message[length - Symmetric.TAG_SIZE:])
            except Exception as ex:
                raise Exception('disco: cannot decrypt the payload')
            
            # append to the input buffer
            self._input_buffer += plaintext

            # read whatever we can read
            rest = count
            rest_to_read = rest if len(self._input_buffer) > rest else len(self._input_buffer)
            data = data[offset:] + self._input_buffer[:rest_to_read]
            if len(self._input_buffer) > rest_to_read:
                self._input_buffer = self._input_buffer[rest_to_read:]
                return count
            
            # we haven't filled the buffer
            self._input_buffer = bytes()
            return rest_to_read
        finally:
            mutex.release()

    def handshake(self) -> None:
        # Locking the handshakeMutex
        self._handshake_mutex.acquire()
        handshake_state : HandshakeState

        try:
            c1 : Strobe = None
            c2 : Strobe = None
            received_payload : bytes
            
            # did we already go through the handshake?
            if (self._handshake_complite):
                return

            # #Q_
            print("handshake!!!!")

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
                if (c1 is not None):
                    break
                # start handshake
                if handshake_state.should_write:
                    buf_to_write : bytes = bytes()
                    proof : bytes
                    if len(handshake_state.message_patterns) <= 2:
                        proof = self._config.static_public_key_proof
                    else:
                        proof = bytes()
                    (c1,c2), buf_to_write = handshake_state.write_message(proof)

                    # header (lenght)
                    length_bytes = bytearray([len(buf_to_write)>>8, (len(buf_to_write) % 256)])
                    self._connection.send(length_bytes + buf_to_write)
                else:
                    buf_header = self.read_from_until(2)
                    length = (buf_header[0] << 8) | buf_header[1]
                    if (length > self._config.NOISE_MESSAGE_LENGTH):
                        raise Exception("disco: Disco message received exceeds DiscoMessageLength")
                    noise_message = self.read_from_until(length)
                    received_payload = bytes()
                    (c1,c2), received_payload = handshake_state.read_message(noise_message)

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
                    self._strobe_out, self._strobe_in = c2, c1
            else:
                self._is_half_duplex = True
                self._strobe_in = c1
                self._strobe_out = c1
        finally:
            # #Q_ tmp
            #handshake_state.__del__()
            # no errors :)
            self._handshake_complite = True
            self._handshake_mutex.release()
    
    @staticmethod
    def _check_requirements(is_client:bool, config:NoiseConfig):
        ht = config.handshake_pattern
        if (ht == NoiseHandshakeType.NOISE_NX 
            or ht == NoiseHandshakeType.NOISE_KX 
            or NoiseHandshakeType == NoiseHandshakeType.NOISE_XX 
            or ht == NoiseHandshakeType.NOISE_IX):
                if is_client and config.public_key_verifier == None:
                    raise Exception('Disco: no public key verifier set in Config')
                if not is_client and config.static_public_key_proof == None:
                    raise Exception('Disco: no public key proof set in Config')
        if (ht == NoiseHandshakeType.NOISE_XN 
            or ht == NoiseHandshakeType.NOISE_XK
            or ht == NoiseHandshakeType.NOISE_XX
            or ht == NoiseHandshakeType.NOISE_X
            or ht == NoiseHandshakeType.NOISE_IN
            or ht == NoiseHandshakeType.NOISE_IK
            or ht == NoiseHandshakeType.NOISE_IX):
                if is_client and config.static_public_key_proof == None:
                    raise Exception('Disco: no public key proof set in Config')
                if not is_client and config.public_key_verifier == None:
                    raise Exception('Disco: no public key verifier set in Config')
        if ht ==NoiseHandshakeType.NOISE_NN_PSK2 and len(config.pre_shared_key) != Symmetric.PSK_KEY_SIZE:
            raise Exception(f'noise: a {Symmetric.PSK_KEY_SIZE}-byte pre-shared key needs to be passed as noise Config')
    
    def authenticate_as_server(self, config : NoiseConfig) -> None:
        self._config = config
        self._isClient = False

        Connection._check_requirements(self._isClient, self._config)
        self.handshake()

    def authenticate_as_client(self, config : NoiseConfig) -> None:
        self._config = config
        self._isClient = True

        Connection._check_requirements(self._isClient, self._config)
        self.handshake()
        