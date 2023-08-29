#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.PublicKey import ElGamal
import Crypto.Random.random as rand
from Crypto.Math import Numbers

class EGKey(ElGamal.ElGamalKey):
    '''Define ElGamal key with "textbook" encryption/decryption 
       implemented (pycryptodome implements ElGamal keys but,
       apparently, no more cryptographic algorithm using those keys)
    '''
       
    def __init__(self,l,randfun=rand.Random.get_random_bytes):
        '''The super __init__ method is useless. pycryptodome includes a
           function to generate ElGamal keys. We generate one and copy
           the dictionary to self.
           Simply returning the generated key would give an ElGamal key
           and not an EGKey'''
        self.__dict__ = ElGamal.generate(l,randfun).__dict__
        
    def publickey(self):
        '''Returns an EGKey public key corresponding to self
           (i.e. without the secret information)
        '''
        pubkey = super().__new__(EGKey)
        pubkey.p = self.p
        pubkey.g = self.g
        pubkey.y = self.y
        return pubkey
    
    def decrypt(self,ciphertext):
        '''Decrypt cipertext using self key'''
        r = Numbers.Integer(ciphertext[0])
        t = Numbers.Integer(ciphertext[1])
        r.inplace_pow(self.x,self.p)
        m = (r.inverse(self.p)*t)%self.p
        return m.to_bytes(self.p.size_in_bytes())
    
    def encrypt(self,plaintext):
        '''Encrypt plaintext using self key'''
        assert len(plaintext) <= self.p.size_in_bytes()
        while (k:=Numbers.Integer.random_range(min_inclusive=1,\
                                               max_inclusive=self.p)) \
               and k.gcd(self.p-1)!=1:
            pass
        h = Numbers.Integer(self.g)  # h = self.g doesn't create a copy
        A = Numbers.Integer(self.y)
        M = Numbers.Integer.from_bytes(plaintext)
        A.inplace_pow(k,self.p)
        return h.inplace_pow(k,self.p),(A*M)%self.p
    
    def sign(self,text):
        assert len(text) <= self.p.size_in_bytes()
        while (k:=Numbers.Integer.random_range(min_inclusive=1,\
                                               max_inclusive=self.p-1)) \
               and k.gcd(self.p-1)!=1:
            pass
        r = Numbers.Integer(self.g)
        r.inplace_pow(k,self.p)
        M = Numbers.Integer.from_bytes(text)
        s = (Numbers.Integer.inverse(k,self.p-1)*(M-r*self.x))%(self.p-1)
        return M,(r,s)
    
    def verify(self,M,r,s):
        r = Numbers.Integer(r)
        A = Numbers.Integer(self.y)
        A.inplace_pow(r,self.p)
        r.inplace_pow(s,self.p)
        x1 = (A*r)%self.p
        x2 = Numbers.Integer(self.g)
        x2.inplace_pow(M,self.p)
        return x1==x2
        
    
    
    