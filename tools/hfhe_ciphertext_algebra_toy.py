#!/usr/bin/env python3
"""Exact reduced-parameter model for HFHE v2's two-layer wrapper.

Models the strongest algebraic abstraction available to a public attacker:
  N0 = R0 (v+m), N1 = R1 (-m) in F_p
  PCi = embed(Ri^-1) G + rhoi H in a prime-order cyclic group Z_q.
Since H=hG in a cyclic group, encode a point by its coefficient of G.
This deliberately gives the attacker every public numerator exactly; edge
partitions/sigmas cannot provide more field information than these sums.
"""
from collections import Counter
from fractions import Fraction

P, Q, H = 31, 13, 5

def inv(x, mod): return pow(x, -1, mod)
def signed(x, p=P): return x if x <= (p-1)//2 else x-p
def emb(x): return signed(x) % Q

def dist(v, commitments=True):
    c = Counter()
    rhos = range(Q) if commitments else (0,)
    for m in range(1, P):
      for r0 in range(1, P):
       for r1 in range(1, P):
        n0 = r0*(v+m) % P
        n1 = r1*(-m) % P
        for rho0 in rhos:
         pc0 = (emb(inv(r0,P)) + H*rho0) % Q
         for rho1 in rhos:
          pc1 = (emb(inv(r1,P)) + H*rho1) % Q
          c[n0,n1,pc0,pc1] += 1
    return c

def tv(a,b):
    na, nb = sum(a.values()), sum(b.values())
    return sum(abs(Fraction(a[k],na)-Fraction(b[k],nb)) for k in a.keys()|b.keys())/2

def marginal(c, f):
    out=Counter()
    for x,n in c.items(): out[f(x)] += n
    return out

def main():
    ds = [dist(v) for v in (0,1,7)]
    for v,d in zip((0,1,7),ds):
        n=sum(d.values())
        z=sum(w for k,w in d.items() if k[0]==0)
        print(f"v={v}: support={len(d)}, Pr[N0=0]={Fraction(z,n)}")
        # Pedersen points are exactly uniform and mutually independent conditioned on N.
        pcs=marginal(d, lambda x:(x[2],x[3]))
        vals=set(pcs.values())
        print(f"  PC pair support={len(pcs)} uniform={len(vals)==1}")
    print("TV(full public tuple, v=1 vs v=7) =", tv(ds[1],ds[2]))
    print("TV(full public tuple, v=0 vs v=1) =", tv(ds[0],ds[1]))
    # Remove the sole exceptional event N0=0; nonzero plaintexts become identical.
    cond=[]
    for d in ds:
        cond.append(Counter({k:w for k,w in d.items() if k[0]!=0}))
    print("TV(condition N0!=0, v=1 vs v=7) =", tv(cond[1],cond[2]))
    # A tempting cancellation T=N0*PC0+N1*PC1 remains uniform due to blindings.
    for v,d in zip((0,1,7),ds):
        t=marginal(d, lambda x:(x[0]*(x[2]) + x[1]*(x[3])) % Q)
        print(f"v={v}: T=N0*PC0+N1*PC1 support={len(t)}, counts={sorted(set(t.values()))}")

if __name__ == '__main__': main()
