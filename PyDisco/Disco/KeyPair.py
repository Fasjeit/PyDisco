class KeyPair(object):
    """description of class"""
    private_key : bytes
    public_key : bytes

    def __del__(self) -> None:
        # todo - clean keys in secure way 
        pass


