import hashlib
from dataclasses import dataclass
from typing import Union, List, Tuple, TextIO, Literal
import secrets

__author__ = 'Quinten'


def H0(data: bytes) -> bytes:
    """ The hash function used to make the public key from the private key"""
    return hashlib.sha3_256(data).digest()


""" The hash function used for the message + new public key"""
H1 = H0


def flat_bytes(list_of_bytes: List[bytes]) -> bytes:
    """
    Takes a list of bytes and returns one bytes by concatenating them
    """
    flat = bytearray()
    for b in list_of_bytes:
        flat.extend(b)
    return flat


@dataclass
class δ0:
    """ The first previous signature (sentinel value) """

    def __iter__(self): yield self

    def __repr__(self): return "δ0()"


@dataclass
class SignatureChain:
    message: bytes
    new_pk: Tuple[List[bytes], List[bytes]]
    proof: List[bytes]
    previous_signature: Union['SignatureChain', δ0]

    @property
    def message_bits(self) -> List[bool]:
        return bytes_to_bits(self.message)

    def to_bytes(self) -> bytes:
        my_bytes = self.message + flat_bytes(self.proof) + OTSkey.pk_to_bytes(self.new_pk)
        if isinstance(self.previous_signature, δ0):
            return my_bytes
        return my_bytes + self.previous_signature.to_bytes()

    def __iter__(self):
        """ returns the previous signatures """
        yield from iter(self.previous_signature)  # First return the other signatures
        yield self  # Then return this signature

    def __repr__(self):
        return f"SignatureChain()"

    def save(self, file: TextIO, format: Literal['toml', 'json'] = None):
        """ Saves the signature to a file """
        if file.name.endswith(".toml") or format == 'toml':
            return export_signature_toml(signature, file)
        else:
            return export_signature_json(signature, file)

    @staticmethod
    def load(file: TextIO, format: Literal['toml', 'json'] = None) -> 'SignatureChain':
        """ Returns a new signature loaded from a file """
        if file.name.endswith(".toml") or format == 'toml':
            return import_signature_toml(file)
        else:
            return import_signature_json(file)


@dataclass
class OTSkey:
    sk: Tuple[List[bytes], List[bytes]]
    pk: Tuple[List[bytes], List[bytes]]

    @property
    def pk_bytes(self) -> bytes:
        """ returns the pk as a bit array """
        return flat_bytes(self.pk[0]) + flat_bytes(self.pk[1])

    @property
    def pk_bits(self) -> List[bool]:
        """ returns the pk as a bit array """
        return bytes_to_bits(self.pk_bytes)

    @staticmethod
    def pk_to_bytes(pk: Tuple[List[bytes], List[bytes]]) -> bytes:
        return flat_bytes(pk[0]) + flat_bytes(pk[1])

    @staticmethod
    def pk_to_bits(pk: Tuple[List[bytes], List[bytes]]) -> List[bool]:
        return bytes_to_bits(OTSkey.pk_to_bytes(pk))

    def save(self, file: TextIO, format: Literal['toml', 'json'] = 'json'):

        if file.name.endswith('toml') or format == 'toml':
            import toml
            saver = toml
        else:
            import json
            saver = json

        key = {
            'pk': ([b64(pk_i) for pk_i in self.pk[0]], [b64(pk_i) for pk_i in self.pk[1]]),
            'sk': ([b64(pk_i) for pk_i in self.sk[0]], [b64(pk_i) for pk_i in self.sk[1]]),
        }

        saver.dump(key, file)

    @staticmethod
    def load(file: TextIO, format: Literal['toml', 'json'] = 'json'):
        if file.name.endswith('toml') or format == 'toml':
            import toml
            loader = toml
        else:
            import json
            loader = json

        key = loader.load(file)
        sk: Tuple[list[str], list[str]] = key["sk"]
        pk: Tuple[list[str], list[str]] = key["pk"]

        pk_decoded = ([b64d(pk_i) for pk_i in pk[0]], [b64d(pk_i) for pk_i in pk[1]])
        sk_decoded = ([b64d(pk_i) for pk_i in sk[0]], [b64d(pk_i) for pk_i in sk[1]])

        return OTSkey(sk_decoded, pk_decoded)

    def save_pk(self, file: TextIO, format: Literal['toml', 'json'] = 'json'):
        if file.name.endswith('toml') or format == 'toml':
            import toml
            saver = toml
        else:
            import json
            saver = json

        pk = {"pk": [[b64(pk_i) for pk_i in self.pk[0]], [b64(pk_i) for pk_i in self.pk[1]]]}
        saver.dump(pk, file)

    @staticmethod
    def load_pk(file: TextIO, format: Literal['toml', 'json'] = 'json') -> Tuple[list[bytes], list[bytes]]:
        """ Loads the public key out of a key file """
        if file.name.endswith('.toml') or format == 'toml':
            import toml
            loader = toml
        else:
            import json
            loader = json

        pk: List[list[str], list[str]] = loader.load(file)["pk"]
        return ([b64d(pk_i) for pk_i in pk[0]], [b64d(pk_i) for pk_i in pk[1]])


@dataclass
class OTSstate:
    message: bytes
    new_pk: Tuple[List[bytes], List[bytes]]
    new_sk: Tuple[List[bytes], List[bytes]]
    proof: List[bytes]

    @property
    def keys(self):
        """ new_pk and new_sk as an OSTkey dataclass"""
        return OTSkey(pk=self.new_pk, sk=self.new_sk)


def randbits(n: int):
    """ random bits of size n (multiple of 8)"""
    assert n % 8 == 0, "n should be multiple of 8"
    return secrets.token_bytes(n // 8)


def bytes_to_bits(byte_string: bytes) -> List[bool]:
    """ Convert a bytes to a list of bool"""
    bits = ''
    for byte in byte_string:
        bits += bin(byte)[2:].zfill(8)
    return [True if x == '1' else False for x in bits]


def genkey() -> OTSkey:
    """
    Generate an OTS key.

    This works like this:
    We got l and n, both integers.

    l is the length of the message

    you generate 2 things, the secret key and the public key
    the secret key is a matrix like:

    [ x_{1,0},  x_{2, 0}, x_{3, 0}, ..., x_{l,0} ]
    [ x_{1, 1}, x_{2, 1}, x_{3, 1}, ..., x_{l,1} ]

    So 2 high and l long.
    - x_{1,0} is the first position of the first row
    - x_{1,1} is the first position of the second row
    - x_{l,0} is the last position of the second row
    - x_{l,1} is the last position of the second row

    So we write an x in the matrix as x_{i,j} with i \in {1, ..., l} and j \in {0,1}

    A specific x_{i, 0} or x_{i, 1} is n long! This is what n is.
    So to make a secret key we do: x_{i, 0} \in {0,1}^n and so also x_{i, 0} \in {0,1}^n
    shorter this is x_{i, 0},x_{i, 0} \in {0,1}^n

    So this you generate. Then you got a matrix from 2 high by l long where every value of the matrix is n long.

    Now to make a public key, you make a new matrix of the same size as the secret key.
        but every value of the public key matrix is the hash of the value in the secret key matrix (in the same position)

    so you get:

    [ y_{1,0},  y_{2, 0}, y_{3, 0}, ..., y_{l,0} ]
    [ y_{1, 1}, y_{2, 1}, y_{3, 1}, ..., y_{l,1} ]

    with every y_{i, j} = H(x_{i,j}) so then you get:

    public key = [ y_{1,0},  y_{2, 0}, y_{3, 0}, ..., y_{l,0} ] = [ H(x_{1,0}),  H(x_{2, 0}), H(x_{3, 0}), ..., H(x_{l,0}) ]
                 [ y_{1, 1}, y_{2, 1}, y_{3, 1}, ..., y_{l,1} ]   [ H(x_{1,0}),  H(x_{2, 0}), H(x_{3, 0}), ..., H(x_{l,0}) ]

    H : {0, 1}^* \leftarrow {0, 1}^*

    l is the length of a message in bits
    n is the length of every item in the secret key matrix

    the length of every item in the public key matrix is the output length of H

    The idea is that you share this public key already to people before you sign something.
    """

    l = 256
    n = 256

    sk = (
        [randbits(n) for _ in range(l)],
        [randbits(n) for _ in range(l)],
    )

    pk = (
        [H0(x) for x in sk[0]],
        [H0(x) for x in sk[1]],
    )

    return OTSkey(pk=pk, sk=sk)


def signOTS(bits: List[bool], sk: Tuple[List[bytes], List[bytes]]) -> List[bytes]:
    """
    Signs a bits with a OTS secret key
    :param bits: The message bits, should be the same size as the secret ke
    :param sk: the secret key (made with keygen)
    :return:

    Start with an empty list as your signature

    The idea is that you sign the hash of a message because that way the message is always length l,
    so you hash the message and then sign the hash. The output length of that message hash function has to be l.

    Start with an empty signature,
    Then you iterate over the bits of that message. If you get a 0 you append (x_{i, 0}, 0) to your signature and if you hit 1 then you append (x_{i, 1}, 1) to your list
    """
    assert len(bits) <= len(sk[0]) and len(bits) <= len(sk[1]), "The secret key is not long enough"
    return [sk[bit][index] for index, bit in enumerate(bits)]


class GeneralOTS:
    """ Class to sign and verify OTS signatures """

    def __init__(self, initial_keys: OTSkey = None, *, debug=False):

        self.state: List[OTSstate] = []
        self.last_signature: Union[SignatureChain | δ0] = δ0()
        self.initial_keys = initial_keys or genkey()
        self.debug = debug

    @property
    def pk(self):
        """ Current pk that you should publish """
        return self.initial_keys.pk

    @property
    def __sk(self):
        """ sk to use for the next signature """
        return self.state[-1].new_sk if self.state else self.initial_keys.sk

    def sign(self, M: bytes) -> SignatureChain:
        """
        The idea is that you sign the hash of your message and the new public key
        :param M: the message you want to sign
        :return:
        """
        new_key = genkey()
        new_sk, new_pk = new_key.sk, new_key.pk
        new_pk_bytes = new_key.pk_bytes

        bytes_to_sign = H1(M + new_pk_bytes)
        bits_to_sign = bytes_to_bits(bytes_to_sign)

        Si_OTS = signOTS(bits_to_sign, self.__sk)
        signature = SignatureChain(message=M, previous_signature=self.last_signature, new_pk=new_pk, proof=Si_OTS)

        self.last_signature = signature
        self.state.append(OTSstate(M, new_pk, new_sk, Si_OTS))

        return signature

    def verify(self, signature: SignatureChain, last_pk: Tuple[List[bytes], List[bytes]]) -> bool:
        """ Verify a signature with a public key"""
        if self.debug:
            print("checking:", signature.message)

        # If the previous signature is an instance of δ0 we know that we now have the last signature in the chain
        is_last_in_chain = isinstance(signature.previous_signature, δ0)

        if is_last_in_chain:
            # If this is the last signature use the last keys (given as input)
            previous_pk = last_pk
        else:  # else get the pk from the previous signature
            previous_pk = signature.previous_signature.new_pk

        # Calculate the bits that decide which pk_i to use by hashing the message and the new pk of this signature using H1
        bits = bytes_to_bits(H1(signature.message + OTSkey.pk_to_bytes(signature.new_pk)))

        valid = True
        # Verify the current signature
        for index, (sk_i, bit) in enumerate(zip(signature.proof, bits)):
            if H0(sk_i) != previous_pk[bit][index]:
                valid = False

        # if there is no previous signature we are done (base case)
        if is_last_in_chain:
            return valid

        # else, check if the previous signature is valid
        return valid and self.verify(signature.previous_signature, last_pk)


def b64(data: bytes) -> str:
    import base64
    encoded_bytes = base64.b64encode(data)
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string


def b64d(data: str) -> bytes:
    import base64
    return base64.b64decode(data)


def export_signature(signature: SignatureChain, out: TextIO):
    if out.name.endswith(".toml"):
        return export_signature_toml(signature, out)
    else:
        return export_signature_json(signature, out)


def import_signature(inp: TextIO):
    if inp.name.endswith(".toml"):
        return import_signature_toml(inp)
    else:
        return import_signature_json(inp)


# If you somehow get the preimages for the other one you didn't use you get forgeries
def export_signature_json(signature: SignatureChain, out: TextIO):
    import json

    sigs = {str(i): {"m": s.message.decode(),
                     'pk': ([b64(pk_i) for pk_i in s.new_pk[0]], [b64(pk_i) for pk_i in s.new_pk[1]]),
                     'proof': [b64(sk_i) for sk_i in s.proof]}
            for i, s in enumerate(signature) if not isinstance(s, δ0)}

    json.dump(sigs, out, sort_keys=True, indent=2)


def export_signature_toml(signature: SignatureChain, out: TextIO):
    import toml

    sig = {str(i): {"m": s.message.decode(),
                    'pk': ([b64(pk_i) for pk_i in s.new_pk[0]], [b64(pk_i) for pk_i in s.new_pk[1]]),
                    'proof': [b64(sk_i) for sk_i in s.proof]}
           for i, s in enumerate(signature) if not isinstance(s, δ0)}
    toml.dump(sig, out)


def import_signature_json(inp: TextIO) -> SignatureChain:
    import json
    sigs = json.load(inp)
    signature = δ0()
    for i in range(1, len(sigs) + 1):
        sig_i = sigs[str(i)]
        message = sig_i['m'].encode()
        proof = [b64d(proof_i) for proof_i in sig_i['proof']]
        new_pk = ([b64d(pk_i) for pk_i in sig_i["pk"][0]],
                  [b64d(pk_i) for pk_i in sig_i["pk"][1]])
        signature = SignatureChain(message=message, proof=proof, new_pk=new_pk, previous_signature=signature)
    return signature


def import_signature_toml(inp: TextIO) -> SignatureChain:
    import toml
    sigs = toml.load(inp)
    signature = δ0()
    for i in range(1, len(sigs) + 1):
        sig_i = sigs[str(i)]
        message = sig_i['m'].encode()
        proof = [b64d(proof_i) for proof_i in sig_i['proof']]
        new_pk = ([b64d(pk_i) for pk_i in sig_i["pk"][0]],
                  [b64d(pk_i) for pk_i in sig_i["pk"][1]])
        signature = SignatureChain(message=message, proof=proof, new_pk=new_pk, previous_signature=signature)
    return signature


if __name__ == "__main__":
    print("\n\nAlice signs 3 messages with secret key:")
    OTS = GeneralOTS()
    pk = OTS.pk

    signature = OTS.sign(b"Quinten")
    print(OTS.verify(signature, pk))

    print(OTS.verify(OTS.sign(b"is"), pk))
    print(OTS.verify(OTS.sign(b"Cool"), pk))

    #  Export the signature
    with open('sig.json', 'w+') as sigfile:
        export_signature(OTS.last_signature, sigfile)

    with open('key.json', 'w+') as keyfile:
        OTS.initial_keys.save_pk(keyfile)

    #  Someone else imports the signature and our public key
    print("\n\nBob imports signature and public key:")
    with open('sig.json', 'r') as sigfile:
        signature_Alice = SignatureChain.load(sigfile)

    with open('key.json', 'r') as keyfile:
        imported_pk = OTSkey.load_pk(keyfile)

    OTSBob = GeneralOTS()  # Someone's else who has our initial pk
    print(OTSBob.verify(signature_Alice, imported_pk))

    # size of 12th signatures (with empty messages)
    print("\nSize of 12th signature:")
    for i in range(12):
        print(f"SignatureChain: {i + 1} = {len(OTS.sign(b'').to_bytes())} bytes")
