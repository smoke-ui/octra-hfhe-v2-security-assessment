#!/usr/bin/env python3
"""Exhaustive toy checks for subgroup/coset leakage in wrapped multiplicative masks."""
from collections import Counter
p, B = 29, 7
# unique subgroup of order 7
H = {pow(2, 4*i, p) for i in range(B)}
F = range(1, p)
def tv(a,b):
    keys=set(a)|set(b); sa=sum(a.values()); sb=sum(b.values())
    return sum(abs(a[k]/sa-b[k]/sb) for k in keys)/2
def q(x): return pow(x,B,p)  # kernel H, hence multiplicative-coset label
# One-layer N=R*v: full-field R hides v; subgroup-only R leaks vH.
full={v:Counter(q(R*v%p) for R in F) for v in F}
restricted={v:Counter(q(R*v%p) for R in H) for v in F}
# Wrapped ratio N0/N1=(R0/R1)*(v+m)/(-m), excluding its genuine zero/pole cases.
def wrapped(v):
 c=Counter()
 for m in F:
  if (v+m)%p==0: continue
  for r0 in F:
   for r1 in F:
    z=(r0*pow(r1,p-2,p)*(v+m)*pow((-m)%p,p-2,p))%p
    c[q(z)]+=1
 return c
vs=[1,2,3,4]
print(f"toy p={p} B={B} H={sorted(H)}")
print("full-mask max TV between nonzero plaintext coset projections:",max(tv(full[a],full[b]) for a in vs for b in vs))
print("subgroup-mask TV for different plaintext cosets:",tv(restricted[1],restricted[2]))
W={v:wrapped(v) for v in vs}
print("wrapped independent-full-mask max TV (conditioned nonzero numerator):",max(tv(W[a],W[b]) for a in vs for b in vs))
print("conclusion: quotient projection leaks only if masks are confined/correlated by coset; full independent masks erase it")
