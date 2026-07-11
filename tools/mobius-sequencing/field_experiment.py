#!/usr/bin/env python3
"""Exact finite-field/order-337 Möbius battery over character sums."""
from __future__ import annotations
import argparse, hashlib, itertools, json, math, pathlib, subprocess, tarfile, tempfile
FIELD=(1<<127)-1
ORDER=337
CORE_MAPS={"identity":(1,0,0,1),"negation":(-1,0,0,1),"inverse":(0,1,1,0),"cayley":(1,-1,1,1)}
PINNED_PVAC="071b0e909c119de815e284b347c4bd979cb59ef3"
PINNED_CHALLENGE="0d08e9622921e5930175a660df0061a65548972f"
REPOSITORIES={"challenge":"octra-labs/hfhe-challenge","pvac":"octra-labs/pvac_hfhe_cpp"}

def canonical_repo_identity(url:str)->str:
 if url.startswith("git@github.com:"):path=url[len("git@github.com:"):]
 elif url.startswith("https://github.com/"):path=url[len("https://github.com/"):]
 else:raise ValueError("unsupported repository origin")
 if path.endswith(".git"):path=path[:-4]
 parts=path.split("/")
 if len(parts)!=2 or not all(parts):raise ValueError("invalid repository identity")
 return "/".join(parts)

def gcd4(m):return math.gcd(*(abs(x) for x in m))
def small_pgl2_maps():
 out=[]
 for raw in itertools.product(range(-2,3),repeat=4):
  if raw==(0,0,0,0) or raw[0]*raw[3]==raw[1]*raw[2]:continue
  g=gcd4(raw);m=tuple(x//g for x in raw)
  if next(x for x in m if x)<0:m=tuple(-x for x in m)
  if m not in out and (m[0]*m[3]-m[1]*m[2])%ORDER:out.append(m)
 return sorted(out)

def fractional_linear(x,m,p=ORDER):
 a,b,c,d=(v%p for v in m)
 if (a*d-b*c)%p==0:raise ValueError("singular map")
 if x is None:return None if c==0 else a*pow(c,-1,p)%p
 den=(c*x+d)%p
 return None if den==0 else (a*x+b)*pow(den,-1,p)%p

def compare_spectra(a,b):
 if len(a)!=ORDER or len(b)!=ORDER:raise ValueError("spectrum must have order 337")
 return {"k_negation":all(a[k]==b[-k%ORDER] for k in range(ORDER)),
         "twist_agreements":[t for t in range(1,ORDER) if all(a[k]==b[t*k%ORDER] for k in range(ORDER))]}

def map_diagnostics(seq,m):
 image=[fractional_linear(x,m) for x in seq];finite=[x for x in image if x is not None]
 return {"zeros":finite.count(0),"poles":len(image)-len(finite),"collisions":len(image)-len(set(image))}

def compare_value_map(a,b,m):
 if len(a)!=ORDER or len(b)!=ORDER:raise ValueError("spectrum must have order 337")
 image=[fractional_linear(x,m,FIELD) for x in a];finite=[x for x in image if x is not None]
 return {"agreements":sum(x is not None and x==y for x,y in zip(image,b)),"zeros":finite.count(0),
         "poles":len(image)-len(finite),"collisions":len(image)-len(set(image))}

def _cross_ratio(a,b,c,d,p=FIELD):
 if None in (a,b,c,d):raise ValueError("infinite cross-ratio coordinate")
 den=((a-d)*(b-c))%p
 return None if den==0 else ((a-c)*(b-d)*pow(den,-1,p))%p

def consecutive_cross_ratios(xs):return [_cross_ratio(*xs[i:i+4]) for i in range(len(xs)-3)]
def pow337(x):return pow(x,ORDER,FIELD)
def seam_ratios(layers):
 if len(layers)!=2 or len(layers[0])!=len(layers[1]):raise ValueError("one equal-width wrapped pair required")
 return [None if x==0 else y*pow(x,-1,FIELD)%FIELD for x,y in zip(*layers)]
def quotient_x337_labels(layers):return [None if x is None else pow337(x) for x in seam_ratios(layers)]

def run_controls():
 a=[pow(7,k,FIELD) for k in range(ORDER)];b=[a[-k%ORDER] for k in range(ORDER)]
 scores=[sum(a[k]==a[t*k%ORDER] for k in range(ORDER)) for t in range(1,ORDER)]
 map_scores=[compare_value_map(a,b,m)["agreements"] for m in small_pgl2_maps()]
 return {"toy_reversal_detected":compare_spectra(a,b)["k_negation"],"coordinate_twists":336,
         "identity_family":scores[0],"max_twist_family":max(scores),"max_map_family":max(map_scores)}

def toy_records():
 a=[pow(7,k,FIELD) for k in range(ORDER)];b=[a[-k%ORDER] for k in range(ORDER)]
 meta={"schema":"pvac-character-spectrum-v2","order":ORDER,"field":"2^127-1","c0_convention":"added_to_every_character_sum","artifact_sha256":"toy"}
 return {"meta":meta,"layers":[{"cipher":0,"layer":0,"slot":0,"rule":"base","spectrum":a},{"cipher":0,"layer":1,"slot":0,"rule":"base","spectrum":b}]}

def parse_extractor(text):
 meta=None;layers=[];ended=False;identities=set()
 lines=text.splitlines()
 for index,line in enumerate(lines):
  try:r=json.loads(line)
  except Exception as e:raise ValueError("malformed extractor JSON") from e
  if not isinstance(r,dict) or "type" not in r:raise ValueError("invalid extractor record")
  if ended:raise ValueError("record after end")
  if r["type"]=="meta":
   if index!=0 or meta is not None or set(r)!={"type","schema","order","field","c0_convention","ciphers"}:raise ValueError("bad metadata")
   if r["order"]!=ORDER or isinstance(r["order"],bool) or r["schema"]!="pvac-character-spectrum-v2" or r["field"]!="2^127-1" or r["c0_convention"]!="added_to_every_character_sum" or r["ciphers"]!=22 or isinstance(r["ciphers"],bool):raise ValueError("bad metadata")
   meta={k:v for k,v in r.items() if k!="type"}
  elif r["type"]=="layer":
   if meta is None or set(r)!={"type","cipher","layer","slot","rule","spectrum"}:raise ValueError("bad layer schema")
   identity=(r["cipher"],r["layer"],r["slot"])
   if not all(isinstance(x,int) and not isinstance(x,bool) for x in identity):raise ValueError("bad layer identity")
   if not (0<=r["cipher"]<22 and r["layer"] in (0,1) and r["slot"]==0) or identity in identities:raise ValueError("bad layer identity")
   spectrum=r.get("spectrum")
   if not isinstance(spectrum,list) or len(spectrum)!=ORDER or not all(isinstance(x,str) and 1<=len(x)<=32 for x in spectrum):raise ValueError("bad spectrum")
   try:vals=[int(x,16) for x in spectrum]
   except ValueError as e:raise ValueError("bad field encoding") from e
   if any(x>=FIELD or format(x,"x")!=encoded for x,encoded in zip(vals,spectrum)):raise ValueError("non-canonical field element")
   if r["rule"]!="base":raise ValueError("bad layer rule")
   identities.add(identity);layers.append({"cipher":r["cipher"],"layer":r["layer"],"slot":r["slot"],"rule":"base","spectrum":vals})
  elif r["type"]=="end":
   if set(r)!={"type","records"} or r["records"]!=44 or isinstance(r["records"],bool) or index!=len(lines)-1:raise ValueError("bad end record")
   ended=True
  else:raise ValueError("unknown record type")
 expected={(c,layer,0) for c in range(22) for layer in range(2)}
 if meta is None or not ended or identities!=expected:raise ValueError("incomplete extractor stream")
 return {"meta":meta,"layers":layers}

def analyze_records(records):
 layers=records["layers"];groups={}
 for x in layers:
  if x.get("rule","base")=="base":groups.setdefault((x["cipher"],x["slot"]),[]).append(x)
 pairs=[];maps=small_pgl2_maps();fixed=((0,1,2,3),(0,1,168,336),(1,84,168,252),(42,126,210,294))
 for key,ls in sorted(groups.items()):
  ls=sorted(ls,key=lambda x:x["layer"])
  if len(ls)<2:continue
  a,b=ls[0]["spectrum"],ls[1]["spectrum"];cmp=compare_spectra(a,b)
  diagnostics=[(m,compare_value_map(a,b,m)) for m in maps];hits=[list(m) for m,d in diagnostics if d["agreements"]==ORDER]
  ratios=seam_ratios([a,b]);labels=quotient_x337_labels([a,b])
  cr_a=[_cross_ratio(*(a[i] for i in q)) for q in fixed];cr_b=[_cross_ratio(*(b[i] for i in q)) for q in fixed]
  pairs.append({"c":key[0],"s":key[1],"neg":cmp["k_negation"],"tw":cmp["twist_agreements"],"maps":hits,
   "core":{name:compare_value_map(a,b,m) for name,m in CORE_MAPS.items()},
   "map_totals":{k:sum(d[k] for _,d in diagnostics) for k in ("zeros","poles","collisions")},
   "seam_unique":len(set(ratios)),"x337_unique":len(set(labels)),"fixed_cross_ratio_equal":sum(x==y for x,y in zip(cr_a,cr_b)),"zero":[a.count(0),b.count(0)]})
 return {"schema":"field-mobius-v2","provenance":records["meta"],"maps_tested":len(maps),"twists_tested":ORDER-1,
  "layer_spectra":len(layers),"wrapped_pairs":len(pairs),"pairs":pairs,"controls":run_controls(),"fixed_cross_ratios":len(fixed),
  "core_maps":{k:list(v) for k,v in CORE_MAPS.items()},"method":"exact-character-sums-field-value-pgl2"}

def _sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def safe_extract_tar(stream,destination):
 destination.mkdir(parents=True,exist_ok=True)
 with tarfile.open(fileobj=stream,mode="r|") as archive:
  for member in archive:
   path=pathlib.PurePosixPath(member.name)
   if path.is_absolute() or ".." in path.parts or not member.name or not (member.isfile() or member.isdir()):
    raise ValueError("unsafe archive member")
   archive.extract(member,destination,filter="data")

def _extract_git_archive(repo,commit,destination):
 proc=subprocess.Popen(["git","-C",str(repo),"archive","--format=tar",commit],stdout=subprocess.PIPE)
 assert proc.stdout is not None
 try:
  safe_extract_tar(proc.stdout,destination)
 except BaseException:
  proc.stdout.close();proc.kill();proc.wait()
  raise
 proc.stdout.close()
 if proc.wait()!=0:raise subprocess.CalledProcessError(proc.returncode,proc.args)

def _git(repo,*args):return subprocess.check_output(["git","-C",str(repo),*args],text=True).strip()
def _validate_repo(repo,commit,identity):
 if _git(repo,"rev-parse","HEAD")!=commit or _git(repo,"status","--porcelain"):raise SystemExit("pinned repository mismatch or dirty")
 try:actual=canonical_repo_identity(_git(repo,"remote","get-url","origin"))
 except ValueError as error:raise SystemExit("repository origin mismatch") from error
 if actual!=identity:raise SystemExit("repository origin mismatch")
 subprocess.run(["git","-C",str(repo),"cat-file","-e",commit+"^{commit}"],check=True)
def run_live(root:pathlib.Path,out:pathlib.Path):
 challenge=root/".deps/hfhe-challenge";pvac=root/".deps/pvac_hfhe_cpp";here=pathlib.Path(__file__).parent
 _validate_repo(challenge,PINNED_CHALLENGE,REPOSITORIES["challenge"]);_validate_repo(pvac,PINNED_PVAC,REPOSITORIES["pvac"])
 with tempfile.TemporaryDirectory() as td:
  archive=pathlib.Path(td);ch=archive/"challenge";pv=archive/"pvac";ch.mkdir();pv.mkdir()
  _extract_git_archive(challenge,PINNED_CHALLENGE,ch)
  _extract_git_archive(pvac,PINNED_PVAC,pv)
  exe=archive/"field_extract"
  subprocess.run(["g++","-std=c++17","-O2","-maes","-msse4.1","-I",str(pv/"include"),"-I",str(ch/"source"),str(here/"field_extract.cpp"),"-o",str(exe)],check=True)
  proc=subprocess.run([str(exe),str(ch/"pk.bin"),str(ch/"secret.ct")],text=True,capture_output=True)
  if proc.returncode:raise SystemExit("extractor rejected pinned artifact: "+proc.stderr.strip())
  records=parse_extractor(proc.stdout)
  records["meta"].update({"challenge_commit":PINNED_CHALLENGE,"pvac_commit":PINNED_PVAC,"pk_sha256":_sha(ch/"pk.bin"),"ciphertext_sha256":_sha(ch/"secret.ct"),"extractor_sha256":_sha(here/"field_extract.cpp"),"source_mode":"validated-git-archives"})
 report=analyze_records(records);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,sort_keys=True,separators=(",",":"))+"\n")
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--root",type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[2]);ap.add_argument("--out",type=pathlib.Path,default=pathlib.Path(__file__).parent/"results/field-mobius.json")
 a=ap.parse_args();run_live(a.root,a.out)
if __name__=="__main__":main()
