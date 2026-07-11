#!/usr/bin/env python3
"""Deterministic bounded real-data BKW-family attacks on pinned OCTRA samples."""
from dataclasses import dataclass
from fractions import Fraction
import argparse, hashlib, io, json, math, pathlib, random, re, subprocess, tarfile, tempfile

@dataclass(frozen=True)
class Equation:
 a:int; y:int; sources:tuple[int,...]
 @property
 def weight(self): return self.a.bit_count()

def _xor(items):
 a=y=0; src=[]
 for row in items: a^=row.a; y^=row.y; src.extend(row.sources)
 return Equation(a,y,tuple(sorted(src)))

def _ratio(x): return {"numerator":x.numerator,"denominator":x.denominator}
def binomial_half_lower_tail(n,weight):
 if n<0: raise ValueError("invalid dimension")
 if weight<0: return Fraction(0)
 if weight>=n: return Fraction(1)
 return Fraction(sum(math.comb(n,k) for k in range(weight+1)),1<<n)

def result_significance(*,effective_random_dimension,weight,candidate_evaluations,actionable,alpha=Fraction(1,100)):
 if candidate_evaluations<=0: raise ValueError("candidate evaluations must be positive")
 tail=binomial_half_lower_tail(effective_random_dimension,weight); fwer=min(Fraction(1),candidate_evaluations*tail)
 classification=("computationally_actionable" if actionable and fwer<=alpha else
                 "statistically_interesting_only" if fwer<=alpha else "bounded_null")
 return {"null_model":"conditioned on each comparison's required projection equality, its residual is uniform on the remaining coordinates; the union bound covers every compared candidate despite dependence and adaptive finalist retention",
         "effective_random_dimension":effective_random_dimension,
         "candidate_evaluations":candidate_evaluations,"random_row_lower_tail":_ratio(tail),
         "family_wise_error_rate":_ratio(fwer),"correction":"conservative_union_bound",
         "alpha":_ratio(alpha),"classification":classification}

def noise_metrics(tau_num,tau_den,k):
 correlation=Fraction(tau_den-2*tau_num,tau_den)**k
 error=(1-correlation)/2
 return {"correlation":_ratio(correlation),"error_probability":_ratio(error),
         "correctness_probability":_ratio(1-error),"centered_bias":_ratio(correlation/2)}

def parameter_estimator(*,n,samples,tau_num,tau_den,blocks,stages):
 return [{"kind":"analytic_estimate","block_bits":block,"stages":stage,
          "combination_size":2**stage,"noise":noise_metrics(tau_num,tau_den,2**stage),
          "fixed_sample_cost":samples,"memory_buckets":min(samples,2**block),
          "terminal_dimension":max(0,n-block*stage)} for block in blocks for stage in stages]

def bucket_cancel(rows,*,n,block_start,block_bits):
 if block_start<0 or block_bits<=0 or block_start+block_bits>n: raise ValueError("invalid block")
 mask=(1<<block_bits)-1; buckets={}
 for row in rows: buckets.setdefault((row.a>>block_start)&mask,[]).append(row)
 out=[]
 for key in sorted(buckets):
  group=buckets[key]
  for i in range(0,len(group)-1,2): out.append(_xor((group[i],group[i+1])))
 return out

def _actionability(*,terminal_dimension,residual_support,criterion):
 checks={"terminal_dimension":terminal_dimension<=criterion["max_terminal_dimension"],
         "residual_direct_budget":(1<<residual_support)<=criterion["max_residual_direct_budget"],
         "terminal_mitm_budget":(1<<((terminal_dimension+1)//2))<=criterion["max_terminal_mitm_budget"]}
 return {"criterion":criterion,"measured":{"terminal_dimension":terminal_dimension,
         "residual_support":residual_support,"residual_direct_budget":1<<residual_support,
         "terminal_mitm_budget":1<<((terminal_dimension+1)//2)},"checks":checks,
         "actionable":all(checks.values())}

def exact_bucket_run(rows,*,n,blocks,tau_num,tau_den,criterion):
 current=rows; stages=[]; work=0
 for stage,(start,width) in enumerate(blocks,1):
  before=len(current); current=bucket_cancel(current,n=n,block_start=start,block_bits=width); work+=before
  stages.append({"block_start":start,"block_bits":width,"input_rows":before,
                 "equations_retained":len(current),"combination_size":2**stage})
 if not current: raise ValueError("bucket run retained no equations")
 best=min(current,key=lambda r:(r.weight,r.sources)); terminal=n-sum(x[1] for x in blocks)
 outcome={"minimum_residual_weight":best.weight,"combination_size":2**len(blocks),
          "work":{"value":work,"unit":"row_visits"},
          "noise":noise_metrics(tau_num,tau_den,2**len(blocks)),"equations_retained":len(current)}
 outcome["actionability"]=_actionability(terminal_dimension=terminal,residual_support=best.weight,criterion=criterion)
 return {"family":"exact_bucket_cancellation","scope":{"rows_examined":len(rows),"stages":len(blocks),
         "row_visits":work,"blocks":[{"start":s,"width":w} for s,w in blocks]},"stages":stages,"outcome":outcome}

def _positions(n,width,rng): return tuple(sorted(rng.sample(range(n),width)))
def _signature(a,positions):
 out=0
 for i,p in enumerate(positions): out|=((a>>p)&1)<<i
 return out

def lsh_nearest(rows,*,n,projection_bits,tables,bucket_cap,top_k,seed):
 if projection_bits>n or min(tables,bucket_cap,top_k)<=0: raise ValueError("invalid LSH bounds")
 rng=random.Random(seed); best={}; comparisons=0; capped=0; projections=[]
 for _ in range(tables):
  pos=_positions(n,projection_bits,rng); projections.append(list(pos)); buckets={}
  for idx,row in enumerate(rows): buckets.setdefault(_signature(row.a,pos),[]).append(idx)
  for key in sorted(buckets):
   ids=buckets[key]; capped+=max(0,len(ids)-bucket_cap); ids=ids[:bucket_cap]
   for at,left in enumerate(ids):
    for right in ids[at+1:]:
     comparisons+=1; pair=(left,right)
     x=rows[left].a^rows[right].a; rank=(x.bit_count(),pair)
     if pair not in best: best[pair]=rank
     if len(best)>top_k:
      worst=max(best,key=lambda p:best[p]); del best[worst]
 if not best: raise ValueError("LSH produced no comparisons")
 weight,pair=min(best.values()); y=rows[pair[0]].y^rows[pair[1]].y
 return {"family":"bounded_all_row_lsh_nearest_pair","scope":{"rows_examined":len(rows),"tables":tables,
  "projection_bits":projection_bits,"bucket_cap":bucket_cap,"top_k":top_k,"comparisons_examined":comparisons,
  "candidate_evaluations_upper_bound":comparisons,"exact_unique_count_not_retained":True,
  "comparisons_include_repeats":True,
  "bucket_overflow_rows_not_compared":capped,"global_deduplicated_finalists":len(best),"projections":projections},
  "outcome":{"minimum_residual_weight":weight,"combination_size":2,"xor_label":y}}

def disjoint_shard_mitm(rows,*,n,shard_size,projection_bits):
 if len(rows)<4*shard_size: raise ValueError("insufficient rows for four disjoint shards")
 shards=[rows[i*shard_size:(i+1)*shard_size] for i in range(4)]
 pairs=[]
 for left in shards[:1]:
  pass
 ab=[(x.a^y.a,x.y^y.y) for x in shards[0] for y in shards[1]]
 cd=[(x.a^y.a,x.y^y.y) for x in shards[2] for y in shards[3]]
 mask=(1<<projection_bits)-1
 def search(left,right,k):
  buckets={}
  for a,y in left: buckets.setdefault((a>>(n-projection_bits))&mask,[]).append((a,y))
  count=0; best=None
  for a,y in right:
   for la,ly in buckets.get((a>>(n-projection_bits))&mask,()):
    count+=1; rank=((a^la).bit_count(),a^la,y^ly)
    if best is None or rank<best: best=rank
  if best is None: raise ValueError("MITM projection produced no match")
  return {"combination_size":k,"minimum_residual_weight":best[0],"xor_label":best[2],"combinations_examined":count}
 triple=search(ab,[(x.a,x.y) for x in shards[2]],3); quad=search(ab,cd,4)
 return {"family":"disjoint_shard_projected_mitm","scope":{"rows_examined":4*shard_size,"shards":4,
  "rows_per_shard":shard_size,"projection_bits":projection_bits,"triple_left_pair_sums":shard_size**2,
  "triple_right_singletons":shard_size,"quad_pair_sums_per_side":shard_size**2,
  "disjoint_assignment":"A+B versus C (triple) and A+B versus C+D (quadruple)"},
  "outcomes":{"triple":triple,"quadruple":quad}}

def experiment(rows,*,n,tau_num,tau_den,seed,blocks,lsh_projection_bits,lsh_tables,lsh_bucket_cap,lsh_top_k,mitm_shard_size,mitm_projection_bits):
 criterion={"max_terminal_dimension":64,"max_residual_direct_budget":1<<64,
            "max_terminal_mitm_budget":1<<32}
 pipeline={"bucket_blocks":[list(x) for x in blocks],"lsh":{"projection_bits":lsh_projection_bits,"tables":lsh_tables,"bucket_cap":lsh_bucket_cap,"top_k":lsh_top_k},"mitm":{"shard_size":mitm_shard_size,"projection_bits":mitm_projection_bits}}
 def run(source):
  bucket=exact_bucket_run(source,n=n,blocks=blocks,tau_num=tau_num,tau_den=tau_den,criterion=criterion)
  bucket_out=bucket["outcome"]
  bucket_out["significance"]=result_significance(effective_random_dimension=n-sum(width for _,width in blocks),weight=bucket_out["minimum_residual_weight"],candidate_evaluations=bucket_out["equations_retained"],actionable=bucket_out["actionability"]["actionable"],alpha=Fraction(1,400))
  lsh=lsh_nearest(source,n=n,projection_bits=lsh_projection_bits,tables=lsh_tables,bucket_cap=lsh_bucket_cap,top_k=lsh_top_k,seed=seed)
  lsh["outcome"]["noise"]=noise_metrics(tau_num,tau_den,2)
  lsh["outcome"]["work"]={"value":lsh["scope"]["comparisons_examined"],"unit":"pair_comparisons_with_repeats"}
  lsh["outcome"]["actionability"]=_actionability(terminal_dimension=n,residual_support=lsh["outcome"]["minimum_residual_weight"],criterion=criterion)
  lsh["outcome"]["significance"]=result_significance(effective_random_dimension=n-lsh_projection_bits,weight=lsh["outcome"]["minimum_residual_weight"],candidate_evaluations=lsh["scope"]["candidate_evaluations_upper_bound"],actionable=lsh["outcome"]["actionability"]["actionable"],alpha=Fraction(1,400))
  mitm=disjoint_shard_mitm(source,n=n,shard_size=mitm_shard_size,projection_bits=mitm_projection_bits)
  for outcome in mitm["outcomes"].values():
   outcome["noise"]=noise_metrics(tau_num,tau_den,outcome["combination_size"])
   outcome["work"]={"value":outcome["combinations_examined"],"unit":"projected_matches_compared"}
   outcome["actionability"]=_actionability(terminal_dimension=n,residual_support=outcome["minimum_residual_weight"],criterion=criterion)
   outcome["significance"]=result_significance(effective_random_dimension=n-mitm_projection_bits,weight=outcome["minimum_residual_weight"],candidate_evaluations=outcome["combinations_examined"],actionable=outcome["actionability"]["actionable"],alpha=Fraction(1,400))
  significances=[bucket_out["significance"],lsh["outcome"]["significance"],
                 mitm["outcomes"]["triple"]["significance"],mitm["outcomes"]["quadruple"]["significance"]]
  global_bound=min(Fraction(1),sum((Fraction(x["family_wise_error_rate"]["numerator"],x["family_wise_error_rate"]["denominator"]) for x in significances),Fraction(0)))
  return {"pipeline":pipeline,"families":[bucket,lsh,mitm],"global_union_bound":_ratio(global_bound)}
 observed=run(rows); rng=random.Random(seed); control=[Equation(rng.getrandbits(n),rng.randrange(2),(i,)) for i in range(len(rows))]
 return {"observed":observed,"matched_random_control":run(control),"design":{"seed":seed,"source_rows":len(rows),"actionability_criterion":criterion,
         "multiple_testing":{"executed_families":4,"global_alpha":_ratio(Fraction(1,100)),
         "per_family_alpha":_ratio(Fraction(1,400)),"correction":"bonferroni_and_capped_global_union_bound"}}}

def compact_json(value):
 text=json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)
 if re.search(r'"(?:path|raw_rows|source_ids)"|/(?:tmp|home|mnt)/',text): raise ValueError("unsafe output")
 return text

PINNED_CHALLENGE="d9d29d505e2840c0028d7a91a2a8ba59e163b9a4"; ORIGIN="octra-labs/hfhe-challenge"
def _git(repo,*args,text=True):
 try:return subprocess.check_output(["git","-C",str(repo),*args],text=text,stderr=subprocess.DEVNULL)
 except (OSError,subprocess.CalledProcessError) as ex: raise ValueError("invalid challenge repository or commit") from ex
def load_pinned(repo):
 url=_git(repo,"remote","get-url","origin").strip().removesuffix(".git"); identity=url.removeprefix("https://github.com/").removeprefix("git@github.com:")
 if identity!=ORIGIN or _git(repo,"rev-parse",PINNED_CHALLENGE+"^{commit}").strip()!=PINNED_CHALLENGE: raise ValueError("challenge identity mismatch")
 payload=_git(repo,"archive","--format=tar",PINNED_CHALLENGE,"SHA256SUMS","lpn_samples",text=False)
 with tempfile.TemporaryDirectory() as td:
  root=pathlib.Path(td)
  with tarfile.open(fileobj=io.BytesIO(payload),mode="r:*") as archive:
   for member in archive.getmembers():
    p=pathlib.PurePosixPath(member.name)
    if p.is_absolute() or ".." in p.parts or not(member.isdir() or member.isfile()): raise ValueError("unsafe archive")
   archive.extractall(root,filter="data")
  hashes={}
  for line in (root/"SHA256SUMS").read_text().splitlines():
   m=re.fullmatch(r"([0-9a-f]{64})  (lpn_samples/ct\d{2}_l[01]_s0_pvac_prf_r_1\.jsonl)",line)
   if m: hashes[m.group(2)]=m.group(1)
  if len(hashes)!=44: raise ValueError("sample manifest mismatch")
  # Validate every immutable split member against the pinned whole-file manifest,
  # but decode labels only from the construction split.
  for name,digest in hashes.items():
   if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest: raise ValueError("sample checksum mismatch")
  selected=[x for x in sorted(hashes) if int(re.search(r"ct(\d{2})",x).group(1))<=17]
  rows=[]; index=0
  for name in selected:
   data=(root/name).read_bytes()
   lines=data.decode("ascii").splitlines(); h=json.loads(lines[0])
   if (h.get("n"),h.get("t"),h.get("tau_num"),h.get("tau_den"))!=(4096,16384,1,8): raise ValueError("sample metadata mismatch")
   for expected,line in enumerate(lines[1:]):
    r=json.loads(line)
    if r.get("i")!=expected or r.get("y") not in (0,1) or not re.fullmatch(r"[0-9a-f]{1024}",r.get("a","")): raise ValueError("invalid row")
    rows.append(Equation(int.from_bytes(bytes.fromhex(r["a"]),"little"),r["y"],(index,))); index+=1
  canonical="".join(f"{hashes[x]}  {x}\n" for x in selected).encode()
  return rows,{"challenge_commit":PINNED_CHALLENGE,"challenge_repository":ORIGIN,"dataset_sha256":hashlib.sha256(canonical).hexdigest(),
   "manifest_files_validated":44,"immutable_whole_file_split":{"construction":{"files":"ct00-ct17","file_count":36,"rows":589824,"labels":"parsed_and_used"},
   "calibration":{"files":"ct18-ct19","file_count":4,"rows":65536,"labels":"unopened_no_candidate_emerged"},
   "final_holdout":{"files":"ct20-ct21","file_count":4,"rows":65536,"labels":"unopened_no_candidate_emerged"}},
   "files":len(selected),"construction_files":"ct00-ct17, both layers","n":4096,"rows":len(rows)}

def main():
 root=pathlib.Path(__file__).resolve().parents[2]; ap=argparse.ArgumentParser(); ap.add_argument("--challenge-repo",type=pathlib.Path,default=root/".deps/hfhe-challenge"); ap.add_argument("--output",type=pathlib.Path); ns=ap.parse_args()
 rows,provenance=load_pinned(ns.challenge_repo)
 report=experiment(rows,n=4096,tau_num=1,tau_den=8,seed=20260711,blocks=((0,12),(12,12)),lsh_projection_bits=16,lsh_tables=4,lsh_bucket_cap=32,lsh_top_k=64,mitm_shard_size=256,mitm_projection_bits=12)
 report.update({"provenance":provenance,"parameter_estimator":parameter_estimator(n=4096,samples=len(rows),tau_num=1,tau_den=8,blocks=(8,12,16),stages=(1,2,3)),"method":"bounded-real-data-bkw-attack"})
 text=compact_json(report)+"\n"
 if ns.output: ns.output.write_text(text)
 else: print(text,end="")
if __name__=="__main__":main()
