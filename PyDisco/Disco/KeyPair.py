#from typing import Optional

class KeyPair(object):
    """description of class"""
    private_key : bytes
    public_key : bytes

    def __del__(self) -> None:
        # todo - clean keys in secure way 
        pass
    def __init__(self, private_key : bytes = bytes(), public_key : bytes = bytes() ):
        self.private_key = private_key
        self.public_key = public_key