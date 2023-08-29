#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May  6 00:07:09 2021

@author: Mauro Leoncini, Univ. of Modena and Reggio Emilia

For teaching purposes only. Makes use of the simplest algorithms

Example usage:
    > E = EllipticCurve(-4,0,227)
    > P = E.getPoints()  # Number of points on the curve y^2=x^3-4x over Z_227
    > print(len(P))
    228
    > O=point(E,Pt_at_Inf) # Point at infinity and group neutral element
    print(O)
    ∞
    # To determine a modulus at least as large as N with a prime order
    # subgroups at least as large as S, for the curve with a = -4 and b = 0,
    # you can use the following command
    > p, primeOrder, points_on_EC = findMod(N,S,-4, 0)
    > g = E.generator()  # Returns a generator for the largest prime subgroup
"""

from Crypto.Util.number import inverse,isPrime
from Crypto.Random.random import randint
from math import sqrt
from ACLIB.utils import factorize,divisors

Pt_at_Inf = (0,1<<100)

class EllipticCurve:
    def __init__(self,a,b,p):
        self.a = a
        self.b = b
        self.p = p
        self.fact = None  # prime factorization of the number of points
        self.O = point(self,Pt_at_Inf)
        
    def _rhs(self,x):
        return ((((x*x)%self.p)*x)%self.p+self.a*x+self.b)%self.p
    
    def includes(self, Q):
        ''' Returns True if and only if point Q lies on the curve '''
        if Q == Pt_at_Inf or Q == self.O: # The point at inifinity belongs to any curve
            return True
        x = Q[0]%self.p
        y = Q[1]%self.p
        fx = self._rhs(x)
        y2 = (y*y)%self.p
        return (y2-fx)%self.p == 0
    
    def getMod(self):
        ''' Returns the modulus of the underlying finite field Z_p '''
        return self.p
    
    def getParams(self):
        ''' Returns the parameters defining the curve '''
        return self.a,self.b,self.p
    
    def tangent(self,p):
        ''' Returns the slope of the tangent line to the
            curve at p
        '''
        z = inverse(2*p[1],self.p)
        return ((((3*p[0]*p[0])+self.a)%self.p)*z)%self.p
    
    def lineThrough(self,p,q):
        ''' Returns the slope of the line intersecting the curve
            at points p and q
        '''
        z = inverse(q[0]-p[0],self.p)
        return ((q[1]-p[1])*z)%self.p
    
    def getPoints(self):
        ''' Returns the list of the points on the curve. 
            Suitable only for very small values of the modulus
            First pre-computes all the possible quadratic residues,
            together with one of its roots (the one in the first half
            of [0,m)). Then computes all the possible right hand sides
            and tries a match with the pre-computed residues
        '''
        P = [self.O]
        squares = {0:0}
        for i in range(1,int((self.p+1)/2)):
            squares[i**2%self.p]=i
        qr = squares.keys()
        for x in range(self.p):
            fx = self._rhs(x)
            if fx==0:
                P.append(point(self,(x,0)))
            elif fx in qr:
                P.append(point(self,(x,squares[fx])))
                P.append(point(self,(x,self.p-squares[fx])))
        return P
    
    def generator(self):
        ''' Finds a generator for the largest prime subgroup of the
            group of all points on the curve. To do this, we pick a 
            random point P on the curve and check whether mP = O (the
            point at infinity), where m is the largest prime factor of
            n (the order of the group of curve points). If this happens,
            since m is prime, <P> must be the desired group.
            Otherwise we pick another random point P and repeat the
            same process
        '''
        L = self.getPoints()
        n = len(L)
        if self.fact is None:
            self.fact = factorize(n)
        m = max(self.fact.primes())
        while True:
            g = L[randint(0,n-1)]
            if g.scalarMult(m) == self.O:
                return g
            
    def order(self,P):
        if self.includes(P):
            if self.fact is None:
                self.fact = factorize(len(self.getPoints()))
            D = sorted(list(divisors(self.fact,True)))
            O = point(self,Pt_at_Inf)
            for d in D:
                if P.scalarMult(d) == O:
                    return d
        raise ValueError("Point does not belong to the curve")
            
class point(tuple):
    ''' Points of elliptic curves are 2-tuple of integers in the underlying
        field that satisfy the curve equation
    '''
    def __new__(cls, ec, P):
        ''' The point at infinity is represented as the pair (-1,-1) '''
        if ec.includes(P):
            self = super().__new__(cls, P)
            self.ec = ec
            return self
        raise ValueError("Point does not belong to the curve")
            
    def neutral(self):
        ''' Point at infinity is the group neutral element '''
        return self == Pt_at_Inf
    
    def __str__(self):
        ''' The point at infinity is printed as "∞" '''
        if self.neutral():
            return u"\u221E"
        return str(super().__str__())
        
    def __neg__(self):
        ''' -X returns the reflected point on the curve '''
        if self.neutral():
            return self
        p = self.ec.getMod()
        return(point(self.ec,(self[0],(-self[1])%p)))
        
    def __add__(self, other):
        ''' Implements point addition '''
        if self==other:
            if self.neutral():
                return self
            elif self==-other:   # Point is (0,0)
                return point(self.ec,Pt_at_Inf)
            else:
                m = self.ec.tangent(self)
        elif self.neutral():
            return other
        elif other.neutral():
            return self
        elif self == -other:
            return point(self.ec,Pt_at_Inf)
        else:
            m = self.ec.lineThrough(self,other)
        p = self.ec.getMod()
        x = ((m*m)%p -self[0]-other[0])%p
        y = (-((m*(x-self[0]))%p+self[1]))%p
        return point(self.ec,(x,y))    
    
    def scalarMult(self, k):
        ''' Computes k*self = self+self+...+self (k times)
        '''
        P = self
        while k>0 and not k&1:
            P = P+P
            k = k >> 1
        Q = P
        k = k >> 1
        while k>0:
            Q = Q+Q
            if k&1:
                P = P+Q
            k = k >> 1
        return P
    
    def order(self):
        return self.ec.order(self)

def findMod(nmin,pmin,a=4,b=0,delta=50):
    ''' Find a suitable modulus n for the curve y^2=x^3+ax+b
        The modulus must be at least as large as nmin and with 
        largest prime factor p>=pmin.
        Returns n and p, and the number np of point on the curve
    '''
    n = (nmin|1)-2
    next_alert = n+delta
    p = -1
    while p<pmin:
        while (n:=n+2) and not isPrime(n):
            pass
        if n>next_alert:
            print(f"Now trying {n}")
            next_alert = n+delta
        E = EllipticCurve(a,b,n)
        np = len(E.getPoints())
        p = max(factorize(np).keys())
    return n, p, np