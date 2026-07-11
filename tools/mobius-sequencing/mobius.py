#!/usr/bin/env python3
"""Core deterministic transforms for Möbius-sequencing experiments."""
from __future__ import annotations


def twisted_partner(index:int,layer:int,width:int,shift:int)->tuple[int,int]:
    return ((width-1-index-shift)%width,1-layer)


def cylinder_partner(index:int,layer:int,width:int,shift:int)->tuple[int,int]:
    return ((index+shift)%width,layer)


def antiperiodic_frequencies(width:int)->list[float]:
    return [k+0.5 for k in range(width)]


def subset_mobius(values:list[int|float])->list[int|float]:
    out=values.copy();bits=(len(out)-1).bit_length()
    if len(out)!=1<<bits:raise ValueError("length must be a power of two")
    for bit in range(bits):
        for mask in range(len(out)):
            if mask&(1<<bit):out[mask]-=out[mask^(1<<bit)]
    return out


def subset_zeta(values:list[int|float])->list[int|float]:
    out=values.copy();bits=(len(out)-1).bit_length()
    if len(out)!=1<<bits:raise ValueError("length must be a power of two")
    for bit in range(bits):
        for mask in range(len(out)):
            if mask&(1<<bit):out[mask]+=out[mask^(1<<bit)]
    return out


def fractional_linear(x:int|None,matrix:tuple[int,int,int,int],prime:int)->int|None:
    a,b,c,d=(v%prime for v in matrix)
    if (a*d-b*c)%prime==0:raise ValueError("singular projective transform")
    if x is None:return None if c==0 else a*pow(c,-1,prime)%prime
    den=(c*x+d)%prime
    return None if den==0 else (a*x+b)*pow(den,-1,prime)%prime


def plus_one_p(exceedances:int,trials:int)->float:
    if not 0<=exceedances<=trials:raise ValueError("invalid permutation counts")
    return (exceedances+1)/(trials+1)


def holm_bonferroni(pvalues:list[float],alpha:float)->list[bool]:
    order=sorted(range(len(pvalues)),key=pvalues.__getitem__);accepted=[False]*len(pvalues)
    for rank,index in enumerate(order):
        if pvalues[index]>alpha/(len(pvalues)-rank):break
        accepted[index]=True
    return accepted


def bit_reverse(value:int,width:int)->int:
    if value<0 or value>=1<<width:raise ValueError("value outside width")
    out=0
    for _ in range(width):out=(out<<1)|(value&1);value>>=1
    return out
