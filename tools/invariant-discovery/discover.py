#!/usr/bin/env python3
"""Train/test public-feature synthesizer with permutation p-values and BH-FDR."""
import argparse,csv,math,random,json
from collections import Counter

def mi(x,y):
 n=len(y); cx=Counter(x);cy=Counter(y);c=Counter(zip(x,y));return sum(v/n*math.log2(v*n/(cx[a]*cy[b])) for (a,b),v in c.items())
def auc_acc(x,y,train,test):
 table={}; glob=Counter(y[i] for i in train).most_common(1)[0][0]
 for v in {x[i] for i in train}:table[v]=Counter(y[i] for i in train if x[i]==v).most_common(1)[0][0]
 return sum(table.get(x[i],glob)==y[i] for i in test)/len(test)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('csv');ap.add_argument('--seed',type=int,default=7341);ap.add_argument('--perms',type=int,default=200);ap.add_argument('--out',default='results.json');a=ap.parse_args();random.seed(a.seed)
 rows=list(csv.DictReader(open(a.csv))); y=[int(r['y']) for r in rows]; base=[k for k in rows[0] if k not in ('id','key_id','y','layers','edges')]
 raw={k:[int(r[k]) for r in rows] for k in base}; fs={}
 mods=(2,3,5,7,11,13,17,31,257,65537)
 for k,v in raw.items():
  for m in mods:fs[f'{k}%{m}']=[z%m for z in v]
  for b in range(16):fs[f'{k}.bit{b}']=[(z>>b)&1 for z in v]
 # Enumerative degree-2 grammar over low-cost residues, including cross-layer pairs.
 seeds={k:v for k,v in fs.items() if k.endswith(('%2','%3','%5','%7','%17','%257'))}
 names=list(seeds)
 for i,p in enumerate(names):
  for q in names[i+1:]:
   if p.split('%')[0]==q.split('%')[0]:continue
   m=int(p.rsplit('%',1)[1]);m2=int(q.rsplit('%',1)[1])
   if m!=m2:continue
   fs[f'({p}+{q})%{m}']=[(u+v)%m for u,v in zip(seeds[p],seeds[q])]
   fs[f'({p}*{q})%{m}']=[u*v%m for u,v in zip(seeds[p],seeds[q])]
 # Key-disjoint split prevents memorizing key-specific public structure.
 keys=sorted({int(r['key_id']) for r in rows}); random.shuffle(keys); cutk=max(1,len(keys)*2//3); trainkeys=set(keys[:cutk])
 tr=[i for i,r in enumerate(rows) if int(r['key_id']) in trainkeys];te=[i for i,r in enumerate(rows) if int(r['key_id']) not in trainkeys]
 if not te: raise SystemExit('need at least two keys for key-disjoint test')
 yt=[y[i] for i in tr]; scored=[]
 for name,x in fs.items():
  obs=mi([x[i] for i in tr],yt); ge=0
  for _ in range(a.perms):
   yp=yt[:];random.shuffle(yp);ge+=mi([x[i] for i in tr],yp)>=obs-1e-15
  scored.append([name,obs,(ge+1)/(a.perms+1),auc_acc(x,y,tr,te),mi([x[i] for i in te],[y[i] for i in te])])
 scored.sort(key=lambda z:z[2]);M=len(scored); discoveries=[]
 for rank,z in enumerate(scored,1):
  z.append(min(1,z[2]*M/rank));
  if z[-1]<=.05:discoveries.append(z)
 out={'n':len(rows),'features':M,'train':len(tr),'test':len(te),'permutations':a.perms,'bh_fdr_05_count':len(discoveries),'top':[dict(zip(('name','train_mi','perm_p','test_accuracy','test_mi','bh_q'),z)) for z in scored[:25]]}
 open(a.out,'w').write(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
main()
