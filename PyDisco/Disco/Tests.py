import unittest
import sys
import binascii
import socket
from Symmetric import Symmetric
from Asymmetric import Asymmetric
from NoiseConfig import NoiseConfig
from NoiseHandshakeType import NoiseHandshakeType

class SymmetricTests(unittest.TestCase):
    def test_hash(self) -> None:
        base_hash = "eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75"
        text_data = bytearray("hi, how are you?", 'UTF8')

        hash = Symmetric()
        target_hash = binascii.hexlify(hash.hash(text_data, hash.HASH_SIZE))

        assert(target_hash != base_hash)

    # def test_sum(self):
    #     message1 = bytearray('hello', 'UTF8')
    #     message2 = bytearray('how are you good sir?', 'UTF8')
    #     message3 = bytearray('sure thing', 'UTF8')

    #     full_message = message1 + message2 + message3

    #     # Trying with NewHash with streaming and without streaming
    #     #var h1 = Hash()
    
    def test_encrypt_decrypt(self) -> None:
        key = bytearray('eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75', "UTF8")
        plaintexts = ["", "a", "ab", "abc", "abcd", "short", "hello, how are you?", "this is very short",
                "this is very long though, like, very very long, should we test very very long things here?",
                "Domestic cats are similar in size to the other members of the genus Felis, typically weighing "
                + "between 4 and 5 kg (9 and 10 lb).[36] Some breeds, such as the Maine Coon, can occasionally "
                + "exceed 11 kg (24 lb). Conversely, very small cats, less than 2 kg (4 lb), have been reported.[59] "
                + "The world record for the largest cat is 21 kg(50 lb).[60][self - published source] "
                + "The smallest adult cat ever officially recorded weighed around 1 kg(2 lb).[60] "
                + "Feral cats tend to be lighter, as they have more limited access to food than house cats."
                + "The Boston Cat Hospital weighed trapped feral cats, and found the average feral adult "
                + "male to weigh 4 kg(9 lb), and average adult female 3 kg(7 lb).[61] Cats average about "
                + "23–25 cm(9–10 in) in height and 46 cm(18 in) in head / body length(males being larger than females), "
                + "with tails averaging 30 cm(12 in) in length;[62] feral cats may be smaller on average.ats have seven"
                + " cervical vertebrae, as do almost all mammals; 13 thoracic vertebrae(humans have 12); seven lumbar"
                + " vertebrae(humans have five); three sacral vertebrae like most mammals(humans have five);"
                + " and a variable number of caudal vertebrae in the tail(humans have only vestigial caudal"
                + " vertebrae, fused into an internal coccyx).[63]:11 The extra lumbar and thoracic vertebrae"
                + " account for the cat's spinal mobility and flexibility. Attached to the spine are 13 ribs,"
                + " the shoulder, and the pelvis.[63] :16 Unlike human arms, cat forelimbs are attached to the"
                + " shoulder by free-floating clavicle bones which allow them to pass their body through any"
                + " space into which they can fit their head.[64]"]
        
        for plaintextString in plaintexts:
            plaintext = bytearray(plaintextString, "UTF8")
            ciphertext = Symmetric.Encrypt(key, plaintext)
            decrypted = Symmetric.Decrypt(key, ciphertext)
            assert(decrypted.decode("utf-8") == plaintextString)
    
    def test_ProtectVerifyIntegrity(self) -> None:
        key = bytearray('eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75', "UTF8")
        mesasge = bytearray('hoy, how are you?', 'UTF8')

        plaintext_and_tag = bytearray(Symmetric.protect_integrity(key, mesasge))
        retrieved_message = Symmetric.verify_integrity(key, plaintext_and_tag)

        assert(mesasge == retrieved_message)

        # Tamper
        plaintext_and_tag[0] ^= 1
        tamperDetected = False

        try:
            Symmetric.verify_integrity(key, plaintext_and_tag)
            tamperDetected = False
        except:
            tamperDetected = True
        assert(tamperDetected)

    def run_one_way_test(self, client_config : NoiseConfig, server_config : NoiseConfig, port : int = 1800) -> None:
        # set up remote keys
        server_config.remote_key = client_config.key_pair.public_key
        client_config.remote_key = server_config.key_pair.public_key

        address = "127.0.0.1"
        server_set_up = False

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((address, port))
        listener.listen(1)

        conn, addr = listener.accept()

        pass
    
    def test_noise_n(self) -> None:
        # init
        client_config = NoiseConfig()
        client_config.key_pair = Asymmetric.generate_key_pair();
        client_config.handshake_pattern = NoiseHandshakeType.NOISE_N

        server_config = NoiseConfig()
        server_config.key_pair = Asymmetric.generate_key_pair();
        server_config.handshake_pattern = NoiseHandshakeType.NOISE_N

        # self.run_one_way_test(client_config, server_config, 1803)



if __name__ == '__main__':
    unittest.main(exit=False)