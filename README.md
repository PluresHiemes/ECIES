ECIES encryption tool.

This tool allows you to generate public and private keys using the Elliptic curves.
simulating Diffie-Helmen key exchange using elliptic curves.

These keys are stored in a Json file.

note code writen in Python 2.

Following task can be performed:

1) Generate keys

        $ python2 ECIES.py genkey mykeys.json

    This will generate a private and public key-pair, using elliptic curves and save them as a json file.

2) encryption

        $ python2 ECIES.py encrypt fileToEncrypt.txt  encryptedResult.txt peerkeys.json ownKeys.json

    This command will encrypt a given text file using peer public key and own private key 

3) decryption

         $ python2 ECIES.py decrypt fileToDecrypt.txt  decryptedResult.txt ownKeys.json

    This command will decrypt a file using own private key and extract peer public key from encrypted file


Test run: 

  1: generate two keys-pairs. one for Alice and one for Bob

        $ python2 ECIES.py genkey AliceKeys.json

        $ python2 ECIES.py genkey BobKeys.json

  2: Encrypt a file using Bob's public key. Only bob will be able to Decrypt it (Alice encrypt a mssage to bob).

        $ python2 ECIES.py encrypt fileToEncrypt.txt  encryptedResult.txt BobKeys.json AliceKeys.json

  3: Decrypt the file using bobs key (bob decrypts Alice's message)

         $ python2 ECIES.py decrypt fileToDecrypt.txt  decryptedResult.txt ownKeys.json
