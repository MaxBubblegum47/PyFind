#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from random import randint
from bisect import bisect_left,insort_left
from os import urandom
from math import sqrt, log2
from functools import reduce

def intsqrt(n):
    '''Returns the integer part of sqrt(n)'''
    assert type(n)==int,"The argument must be an integer"
    assert n>=0,"The argument must be a positive integer"
    if n <= 1:
        return n  
    # If n is (relatively) small, we assume rounding error will not affect the result
    if n < 1>>32:
        return int(sqrt(x))
    r0 = n>>1                    # Initial (loose) approximation
    while True:
        r = (r0 + n // r0) >> 1  # Average value
        if r >= r0:
            return r
        r0 = r

def Euclid(x,y):
    '''Computes the MCD of x and y using Euclid's algorithm'''
    if y==0:
        return x
    return Euclid(y,x%y)

def extended_Euclid(x,y):
    '''Computes integer m,a,b such that m = gcd(x,y) and
       m = ax+by holds.'''
    if y==0:
        return x,1,0
    m,a,b = extended_Euclid(y,x%y)
    # Per ipotesi induttiva vale: m = a y + b (x%y)  e m = MCD(y,x mod y) = MCD(x,y)
    return m,b,a-b*(x//y)

def modular_inverse(x,n):
    '''Computes 1/x mod n'''
    m,a,b=extended_Euclid(x,n)
    if m == 1:
        return a%n
        
def rand(n,start_at=0):
    '''Generates a random integer in the range [start_at,n)'''
    b = int(log2(n)/8)+1
    r = int.from_bytes(urandom(b),'big')/(1<<(8*b))
    return int(r*(n-start_at))+start_at

def modprod(a,b,n):
    '''Computes the product ab mod n using additions and shifts only. 
       For the computation of remainders x mod n, we note that x is always
       less than 2n (except possibly for the input parameters a and b).
       Hence integer division is not required.
    '''
    def easymod(x):
        'x<2n, always'
        nonlocal n
        if x>=n:
            return x-n
        return x
    if b==0:
        return 0
    a = a%n              # If a>n replace a with a mod n
    b = b%n              # Idem
    z = 0                # z accumulates the partial sums a2^k
    while b>0:
      if b&1:            # Use the current value of a if needed
        z = easymod(z+a)  
      a = easymod(a<<1)  # prepare for the next step
      b = b >> 1         # shift b
    return z

def modexp(a,b,n):
    'Efficiently computes a^b mod n.'
    a = a%n     # If a>n, replaces it with a mod n (of course, this cannot be made with b)
    if b<0:
        a = modular_inverse(a,n)
        b = -b
    p = 1       # p accumulates the partial products a^(2^k)
    while b>0:
        if b&1: # If the rightmost bit of b is 1, the current value of a must be used
            p = modprod(p,a,n)
        a = modprod(a,a,n)   # prepare for the next step
        b = b >> 1           # shift b
    return p
    
def isQuadraticResidue(a,p):
    '''p must be prime. Return 1 if a is a quadratic residue 
       and -1 (i.e., p-1) otherwise. Implements Euler's criterion
    '''
    return modexp(a,(p-1)>>1,p)

def modsqrt(a,p):
    ''' Returns one of the two square roots of a mod p.
        a must be already known to be a quadratic residue mod p,
        which means a^{(p-1)/2}=1 mod p
    '''
    assert isQuadraticResidue(a,p)==1,f"{a} is not a quadratic residue mod {p}"
    
    if p&3==3: # The easy case
        r = modexp(a,(p+1)>>2, p)
        return r,p-r

    # else p = 1 mod 4, the not so easy case

    # The algorithm needs a quadratic "non residue" mod p
    # Since they are abundant, we can simply try one
    # at random, check whether is a q.n.r. and possibly repeat
    b = randint(1,p-1)
    while isQuadraticResidue(b,p)==1:
        b = randint(1,p-1)

    # Now, compute a "partial factorization of p-1 as t2^s
    # where m is odd
    t = p-1 
    s = 0
    while not t&1:
        s += 1
        t = t >> 1

    # Next, compute the inverse of a mod p using the extended euclidean algorithm
    a1 = modular_inverse(a,p)

    # Also compute b^t mod p and a^(t+1) mod p
    c = modexp(b,t,p)    # By construction c^{2^{s-1}} mod p = -1
    r = modexp(a,(t+1)>>1,p)

    for i in range(1,s):
        d = modexp(modprod((r*r)%p,a1,p),1<<s-i-1,p)
        if d==(-1)%p:
            r = modprod(r,c,p)
        c = (c*c)%p
    return r,p-r

def jacobiS(a,n):
    '''Computes the Jacobi simbol (a/n). It is assumed (in the top leve call)
       the n is an odd positive integer'''
    if a%n==0:     # By definition
        return 0
    if a==1:       # Also by definition, as the product of Legendre symbols
        return 1
    if a==2:       # Apply property 4 (see primalita.ipynb notebook)
        return 1 if n%8==1 or n%8==7 else -1
    if a%2==0:     # Apply property 1 (see primalita.ipynb notebook)
        return jacobiS(2,n)*jacobiS(a//2,n)
    if a>n:        # Apply property 2 (see primalita.ipynb notebook)
        return jacobiS(a%n,n)
    if a%4==3 and n%4==3:     # Otherwise, apply property 3 (see primalita.ipynb notebook)
    	return -jacobiS(n,a)  # checking for the case a=n=3 (mod 4)
    return jacobiS(n,a)
    
class subgroup(set):
    '''
    Class defining a hashable set
    '''
    def __hash__(self):
        return 0
        
def distinct_powers(g,p):
    '''
    Returns the subgroup H={1,g,g^2,...,g^{m-1}} of Zp*, where
    m>0 is minimum positive integer such that g^m=1 (mod p).
    Pay attention that no check is made on the parameter correctedness.
    '''
    H = [1]
    v = g
    while v!=1:
        H.append(v)
        v = (v*g)%p
    return subgroup(H)
    
def Solovay_Strassen(n,k=10):
    '''Randomized compositeness test based on Solovay-Strassen algorithm'''
    assert type(n)==int and n>2 and n&1
    for _ in range(k):
        a = randint(1,n-1)
        if Euclid(a,n)>1:
            return True
        if jacobiS(a,n)%n != modexp(a,(n-1)>>1,n):
            return True
    return False
    
def isPrime(n):
    if not n&1:
        return False
    return not Solovay_Strassen(n)
    
def getprime(n):
    '''Return a randomly chosen prime'''
    p = rand(n,3)|1
    while Solovay_Strassen(p):
        p = rand(n,3)|1
    return p

def safeprime(b):
    '''Returns a b bytes safe prime'''
    while True:
        while (p:=int.from_bytes(urandom(b),'big')|1) and not isPrime(p):
            pass
        if isPrime((p<<1)+1):
            return (p<<1)+1

class lookuptabled(dict):
    def __new__(cls,*args):
        self = super().__new__(cls)
        return self
    def __init__(self,k=None,v=None):
        if k is not None:
            self[k]=v
    def __getitem__(self,k):
        v = super().get(k,None)
        return v

class lookuptablel:
    def __init__(self,k=None,v=None):
        self.L = []
        if k is not None:
            self.L.append((k,v))
    def __getitem__(self,k):
        pos = bisect_left(self.L,(k,-1))
        if pos<len(self.L):
            p = self.L[pos]
            if p[0]==k:
                return p[1]
        return None
    def __setitem__(self,k,v):
        insort_left(self.L,(k,v)) 
    def __repr__(self):
        return str(self.L)
    
def BSGS(g,x,n,lookuptable=lookuptabled,rmax=10**8):
    '''Computes the discrete logarithm a=log_g x mod n,
       where g is a primitive root of the multiplicative group Z*_n.
       Uses the Baby-steps Giant-steps algorithm with rmax default
       maximum number of baby steps.
    '''
    r = min(intsqrt(n)+1,rmax); s = (n // r) + 1
    # Start baby-steps
    bs = lookuptable(1,0)     # First pair in the baby-steps lookup table
    v = g                     # v = g^1 mod n = g (assuming g<n)
    for i in range(1,r):
        bs[v]=i
        v = modprod(v,g,n)
    # Start giant-steps
    gr = modexp(modular_inverse(g,n),r,n)
    R = 0
    xr = x
    while R<s*r:
        e = bs[xr]
        if e is not None:
            return (e+R)%n
        xr = modprod(xr,gr,n)
        R += r
    return None

def pollard_rho(n):
    '''Implements the Pollard's rho heuristics and (possibly)
       returns a non-trivial divisor of n.
       Strictly follows the description in 
       Cormen et al. Introduction to Algorithms, Third ed. 
    '''
    i,j = 2,1
    xprec = rand(n)  # xprec = x_1
    y = xprec        # Salvataggio del primo valore
    while True:
        j += 1
        x = (xprec*xprec - 1)%n            # calcolo iterata successiva
        if (p:=Euclid(y-x,n))!=1 and p!=n:
            return p
        if j==i:
            y = x
            i *= 2
        xprec = x

class primefact(dict):
    '''Simple class to represent factorizations'''
    def __new__(cls,*args):
        return super().__new__(cls,{})
    def __init__(self,*args):
        assert not len(args)&1, "Wrong arguments"
        for i in range(0,len(args),2):
            self[args[i]]=args[i+1]
    def primes(self):
        return set(self.keys())
    def __repr__(self):
        return " * ".join([str(p) if e==1 else str(p)+"**"+str(e) for p,e in self.items()])
    def merge(self,other):
        for k in self.primes().union(other.primes()):
            self[k]=self.get(k,0)+other.get(k,0)
            
def BruteForceFact(n):
    '''Computes the prime facorization using brute force.
       Use carefully for small (and odd) values of n 
    '''
    assert n&1, "n must be odd"
    F = primefact()
    while n>1 and not isPrime(n):
        for i in range(3,int(sqrt(n))+1,2):
            if n%i==0:
                F.merge(primefact(i,1))
                n=n//i
                break
    if n>1:
        F.merge(primefact(n,1))
    return F

def factorize(n,nmax=10**6):
    '''Return the prime factorization of n'''
    def fact(n):
        '''Inner function that actually does the heavy job
           Uses brute force for small n and Pollard's rho otherwise
           Not guaranteed to terminate, since pollard_rho 
           occasionally does not halt
        '''
        if n<=nmax:
            return BruteForceFact(n)
        elif isPrime(n):
            return primefact(n,1)
        f = pollard_rho(n)
        F = fact(f)
        F.merge(fact(n//f))
        return F
    # We first deal with the case n=p 2^q and compute q (p is odd)
    i = 0
    while not n&1:
        i += 1
        n = (n>>1) 
    if i==0:
        d = primefact()
    else:
        d = primefact(2,i)
    # What remains is p
    if n != 1:
        d.merge(fact(n))
    return d

def divisors(N,pf=False):
    '''Generate all the possible (proper) divisors of the number N
       given in input. Possibly, N is already the prime factorization
       of the number whose divisors must be computed.
       The divisors are typically used to test for primitive roots. 
    '''
    if not pf:
        pf = factorize(N)
    else:
        pf = N
    primes = list(pf.primes())
    exps = [pf[p] for p in primes]
    n = len(primes)
    # Now we generate all the possible vectors of exponents
    # that characterize a proper divisor
    x = [1]+[0]*(n-1)   # Start with [1,0,...,0]
    D = primes[0]
    while sum(x)<sum(exps):
        yield D
        for i in range(n):
            if x[i]<exps[i]:
                x[i]+=1
                D *= primes[i]
                break
            x[i]=0
            D = D//(primes[i]**exps[i])

def primitive_root(a,p):
    '''Test whether a is a primitive root of Z*_p, for prime p
    '''
    for d in divisors(p-1):
        if modexp(a,d,p)==1:
            return False
    return True

def CRT(x,*mods):
    '''Chinese Remaindering: direct mapping'''
    return tuple(x%m for m in mods)

def CRTInv(*args):
    '''Chinese Remaindering: inverse mapping
       There must be an even number of arguments: 
       first half  -> values
       second half -> moduli
       x = CRTInv(*CRT(x,p1,...,pk),p1,...,pk)
    '''
    assert len(args)%2 == 0, "There must be an even number of arguments"
    n = len(args) >> 1       
    N = reduce(lambda y,z: y*z, args[n:])
    x = 0
    for i in range(n):
        M = N // args[n+i]
        I = M*(modular_inverse(M,args[n+i]))
        x = (x+modprod(I,args[i],N))%N
    return x

def linsearchlog(a,b,n):
    '''Computes the discrete logarithm x=log_a b mod n,
       where a is a primitive root of the multiplicative group Z*_n.
       Uses linear search so it's very inefficient unless the order
       of a is small
    '''
    x = 0
    while x<n:
        if modexp(a,x,n) == b:
            return x
        x+=1
    return None

def Pohlig_Hellman2(g,x,p,q,c,basealg):
    '''Computes (log_g(x) mod p) mod q^c, assuming q is a
       prime factor of p-1 (with corresponding exponent c)
    '''
    qp = (p-1)//q
    gp = modexp(g,qp,p)
    g1 = modular_inverse(g,p)
    Q = 1
    a = 0
    for j in range(c-1):
        aj = basealg(gp,modexp(x,qp//Q,p),p)%q
        x = modprod(x,modexp(g1,aj*Q,p),p)
        a += aj*Q
        Q *= q
    aj = basealg(gp,modexp(x,qp//Q,p),p)%q
    a += aj*Q
    return a

def Pohlig_Hellman(g,x,p,basealg=linsearchlog):
    '''Computes the discrete logarithm y=log_g x mod a prime p,
       where g is a primitive root of the multiplicative group Z*_p.
       Uses the Pohlig-Hellman algorithm as explained by a 
       short note by D. R. Stinson
    '''
    pf = factorize(p-1)
    factors = [q**pf[q] for q in pf.primes()]
    L = [Pohlig_Hellman2(g,x,p,q,pf[q],basealg) for q in pf.primes()]
    return CRTInv(*L+factors)

