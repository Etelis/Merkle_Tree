import base64
import hashlib
import math
import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes


def create_RSA():
    """
    create an RSA private and public keys for later root signing.
    """
    keys = ''
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    keys += pem.decode('utf-8')
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    keys += pem.decode('utf-8')


def validate_signature(key, signature, text):
    """
    validate provided signature.
    """
    base64_signature = base64.decodebytes(signature.encode())
    text = text.encode()
    key = key.encode()
    public_key = serialization.load_pem_public_key(key)
    try:
        public_key.verify(base64_signature, text, padding.PSS(padding.MGF1(hashes.SHA256()),
                                                              padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        print("True")
    except cryptography.exceptions.InvalidSignature:
        print("False")


class MerkleTree:
    """
    Merkle Tree implementation, hash function used is 'SHA256'.
    Root is recostructed upon every leaf addon, the list of leaves is persistent.
    """

    def __init__(self):
        self.leaves = []
        self.root = self._evaluate()

    def _insert_leaf(self, value):
        """
        Add a single leaf to the tree. for every leaf added the tree will be reconstructed.
        """
        self.leaves.append(hashlib.sha256(value.encode('utf-8')).hexdigest())
        self._evaluate()

    def _root(self):
        return self.root

    def _evaluate(self):
        """
        Used to construct the tree and arrive at the block header
        """

        if len(self.leaves) == 0:
            return None

        current_level = list(self.leaves)
        while len(current_level) > 1:
            current_level = self._evaluate_next_level(current_level)

        return current_level[0]

    def _evaluate_next_level(self, current_level):
        """
        Constructs the next level of the tree, this function will be called for each level to be created,
        final level would be the root.
        """
        next_level_nodes = []
        if len(current_level) % 2 == 0:
            for i in range(0, len(current_level), 2):
                next_level_nodes.append(
                    hashlib.sha256((current_level[i] + current_level[i + 1]).encode('utf-8')).hexdigest())

        else:
            for i in range(0, len(current_level) - 1, 2):
                next_level_nodes.append(
                    hashlib.sha256((current_level[i] + current_level[i + 1]).encode('utf-8')).hexdigest())
            next_level_nodes.append(current_level[-1])
        return next_level_nodes

    def create_proof_of_inclusion(self, index):
        """
        function will be used to create proof of inclusion for a given node indexed at 'index'
        1 at the beginning will note that leaf is assigned from the right,
        whether if a zero presents meaning leaf will be assigned from the left.
        """
        proof_string = self.root

        # Sanity check.
        if self.root == "" or index >= len(self.leaves):
            return

        current_level = list(self.leaves)
        # iterate on the tree while building it, for each level include proper proof.
        while len(current_level) > 1:
            # left node.
            if index % 2 == 0:
                # sanity check, make sure left brother does exist.
                if index is not len(current_level) - 1:
                    proof_string += " 1{}".format(current_level[index + 1])
            else:
                # right node.
                if index != 0:
                    # sanity check - make sure right brother does exist.
                    proof_string += " 0{}".format(current_level[index - 1])

            index = math.ceil(index / 2)
            # evaluate next level.
            current_level = self._evaluate_next_level(current_level)
        return proof_string

    def verify_proof_of_inclusion(self, value, proof):
        """
        for a given proof verify the proof is indeed for the provided value.
        """
        # hash value
        value = hashlib.sha256(value.encode('utf-8')).hexdigest()
        proofs = list(proof.split(" "))

        # if root wasn't at the beginning of the proof, proof is invalid.
        if proofs[0] != self.root:
            return False
        try:
            # try finding the value in leaves array.
            self.leaves.index(value)
        except ValueError:
            return False
        # verify proof.
        for i in range(1, len(proofs)):
            value = hashlib.sha256((value + proofs[i][1:]).encode('utf-8')).hexdigest()
        if value == self.root:
            return True
        return False

    def sign_root(self, private_key):
        """
        sign the root of the tree with the provided private key.
        """
        sign = private_key.sign(
            self.root.encode(),
            padding.PSS(padding.MGF1(hashes.SHA256()),
                        padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return base64.b64encode(sign).decode()
