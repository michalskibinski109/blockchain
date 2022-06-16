from time import time
import numpy as np
from hashlib import sha256, sha512
from Crypto.PublicKey import RSA


class Transaction:
    '''
    Class for transaction
    '''

    def __init__(self, amount, payer, payee) -> None:
        """ Class for transaction\n
        Args:
            amount: amount of money payed.
            payer: user who is paying.
            payee: user who is getting paid.
        """
        self.amount = amount
        self.payer = str(payer)
        self.payee = str(payee)

    def to_str(self) -> str:
        return str(self.amount) + '-' + self.payer + '-' + self.payee


class Block:
   
    def __init__(self, previous_block_hash, transaction_list) -> None:
        """ Class for single operation\n
        Args:
        """
        self.NONCE = np.random.randint(0, 10e7)
        self.transaction_list = transaction_list
        self.__previous_block_hash = previous_block_hash
        self.date = time()
        self.block_data = str(self.transaction_list) + \
            '-' + str(self.__previous_block_hash)

    def hashed(self):
        return sha256(self.block_data.encode()).hexdigest()


class Chain:
    """Chain class
    Note:
        Create only one instance of this class
    Attributes:
        mine(): simple function for mining crypto Currency.
        addBlock(): function designed to add blocks to current chain. Checks validation of every transactions.

    """
    def __init__(self) -> None:
        self.chain = [Block(None, Transaction(0, 'a', 'b'))]

    def lastBlock(self):
        return self.chain[-1]

    def mine(self, NONCE: int):
        sol = 1
        print('⛏️  mining...')
        while sol != NONCE:
            sol += 1
        print(sol)
        return sol

    def addBlock(self, transaction: Transaction, senderPublicKey: str, signature):
        msg = bytes(transaction.to_str(), encoding='utf-8')
        hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
        hashFromSignature = pow(
            signature, senderPublicKey.e, senderPublicKey.n)
        if hash == hashFromSignature:
            print("Signature valid:", hash == hashFromSignature)
            newBlock = Block(self.lastBlock().hashed(), transaction)
            self.mine(newBlock.NONCE)
            self.chain.append(newBlock)

    def __make_transaction(self, transaction: Transaction):
        transaction.payer


class Wallet:
    '''Class for single account.
    Note:
        every instance of class auto-generates key pair

    Attributes:
        money: Human readable string describing the exception.
        KeyPair: public and private keys
        sendMoney(): function for sending money
    '''
    def __init__(self) -> None:
        self.__keyPair = RSA.generate(1024)
        self.__privateKey = self.__keyPair
        self.publicKey = self.__keyPair.publickey()
        self.money = 0

    def sendMoney(self, chain: Chain, amount: float, payeePublicKey: str):
        transaction = Transaction(amount, self.publicKey, payeePublicKey)
        msg = bytes(transaction.to_str(), encoding='utf-8')
        hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
        signature = pow(hash, self.__keyPair.d, self.__keyPair.n)
        chain.addBlock(transaction, self.publicKey, signature)


class User(Wallet):
    """user class just to make future account for `Wallet` owners
        it is not relative to working of blockchain system. 
    Args:
        username: username of wallet's owner.
    """
    def __init__(self, username) -> None:
        super().__init__()
        self.username = username
        self.money = 0

    def __str__(self) -> str:
        return f'username: {self.username}\n\
            \npublic Key: {self.publicKey}\nmoney on account {self.money}'


model = Chain()
satoshi = User('satoshi')
bob = User('bob')
alice = User('bob')

satoshi.sendMoney(model, 50, bob.publicKey)
bob.sendMoney(model, 23, alice.publicKey)
alice.sendMoney(model, 5, bob.publicKey)
