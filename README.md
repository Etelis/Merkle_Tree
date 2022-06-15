# Merkle Tree implemntation and explenation. 

## Introduction

In cryptography and computer science, a hash tree or Merkle tree is a tree in which every "leaf" (node) is labelled with the cryptographic hash of a data block, and every node that is not a leaf (called a branch, inner node, or inode) is labelled with the cryptographic hash of the labels of its child nodes. A hash tree allows efficient and secure verification of the contents of a large data structure. A hash tree is a generalization of a hash list and a hash chain. 

![Merkle Tree](https://prathamudeshmukh.github.io/merkle-tree-demo/ "Merkle Tree")
_Source: [Wikipedia+](https://en.wikipedia.org/wiki/Merkle_tree)_

Above you could see a simulator designed to demostrate how merkle trees actually looks.

## Usage in bitcoin's block chain.

In bitcoin's blockchain, a block of transactions is run through an algorithm to generate a hash, which is a string of numbers and letters that can be used to verify that a given set of data is the same as the original set of transactions, but not to obtain the original set of transactions. Bitcoin's software does not run the entire block of transaction data—representing 10 minutes' worth of transactions on average—through the hash function at one time, however.
Rather, each transaction is hashed, then each pair of transactions is concatenated and hashed together, and so on until there is one hash for the entire block. (If there is an odd number of transactions, one transaction is doubled and its hash is concatenated with itself.) 

![Merkle Proof](img/merkle_proof.jpeg "Merkle Proof")
_Source: [Investopedia](https://www.investopedia.com/terms/m/merkle-tree.asp)_

### Implementation

The implementation is rather simple, the merkle tree wont be saved as a structur but will only save data-leaves making it efficient in storage constructing the tree for each operation.

The code allows the user to create a tree and append new leaves to it, a user could also generate proof of inclusion for every leaf in the tree.
For a given proof of inclusion the stracture will be able to verify the authenticity of it


Writing your own tests is not required but highly recommended. 

