#!/usr/bin/env python3
"""Deterministic, fail-closed Möbius sequencing battery for published LPN (A,y)."""
from __future__ import annotations
import argparse, dataclasses, hashlib, io, json, math, pathlib, random, re, subprocess, tarfile, tempfile
import numpy as np
from typing import Iterable

FORMAT="octra-bounty-target-seed-lpn-ay-v1"
PINNED_CHALLENGE="d9d29d505e2840c0028d7a91a2a8ba59e163b9a4"
CHALLENGE_REPOSITORY="octra-labs/hfhe-challenge"
HEADER_KEYS={"format","cipher_index","layer_id","slot","dom","n","t","tau_num","tau_den","row_words","seed_ztag","nonce_lo_hex","nonce_hi_hex","public_T_hex"}
ROW_KEYS={"i","y","a"}
NAME=re.compile(r"ct(\d{2})_l([01])_s0_pvac_prf_r_1\.jsonl\Z")
@dataclasses.dataclass(frozen=True)
class Sample:
 cipher:int; layer:int; n:int; rows:tuple[tuple[int,int,int],...]

def _repository_identity(url:str)->str:
 if url.startswith("git@github.com:"): value=url[len("git@github.com:"):]
 elif url.startswith("https://github.com/"): value=url[len("https://github.com/"):]
 else: raise ValueError("challenge repository origin mismatch")
 if value.endswith(".git"): value=value[:-4]
 if value!=CHALLENGE_REPOSITORY: raise ValueError("challenge repository origin mismatch")
 return value

def safe_extract_archive(payload:bytes,destination:pathlib.Path)->None:
 destination=destination.resolve()
 with tarfile.open(fileobj=io.BytesIO(payload),mode="r:*") as archive:
  for member in archive.getmembers():
   parts=pathlib.PurePosixPath(member.name)
   if parts.is_absolute() or ".." in parts.parts or not member.name or not (member.isdir() or member.isfile()): raise ValueError("unsafe archive entry")
   target=(destination/pathlib.Path(*parts.parts)).resolve()
   if destination not in target.parents and target!=destination: raise ValueError("unsafe archive path")
  archive.extractall(destination,filter="data")

def _git(repo:pathlib.Path,*args:str,text:bool=True):
 try: return subprocess.check_output(["git","-C",str(repo),*args],text=text,stderr=subprocess.DEVNULL)
 except (OSError,subprocess.CalledProcessError) as ex: raise ValueError("invalid challenge repository or commit") from ex

def load_challenge_dataset(repo:pathlib.Path,*,commit:str=PINNED_CHALLENGE,expected_ciphertexts:int=22,analyzer:pathlib.Path|None=None)->tuple[list[Sample],dict]:
 repo=repo.resolve(); identity=_repository_identity(_git(repo,"remote","get-url","origin").strip())
 resolved=_git(repo,"rev-parse",commit+"^{commit}").strip()
 if resolved!=commit: raise ValueError("challenge commit mismatch")
 payload=_git(repo,"archive","--format=tar",commit,"SHA256SUMS","lpn_samples",text=False)
 with tempfile.TemporaryDirectory() as td:
  root=pathlib.Path(td); safe_extract_archive(payload,root); manifest=(root/"SHA256SUMS").read_bytes()
  try: lines=manifest.decode("ascii").splitlines()
  except UnicodeDecodeError as ex: raise ValueError("invalid checksum manifest") from ex
  expected={f"lpn_samples/ct{c:02d}_l{l}_s0_pvac_prf_r_1.jsonl" for c in range(expected_ciphertexts) for l in range(2)}; hashes={}
  for line in lines:
   match=re.fullmatch(r"([0-9a-f]{64})  (lpn_samples/[^/]+\.jsonl)",line)
   if match:
    digest,name=match.groups()
    if name in hashes: raise ValueError("duplicate checksum entry")
    hashes[name]=digest
  if set(hashes)!=expected: raise ValueError("checksum manifest sample set mismatch")
  for name,digest in hashes.items():
   path=root/name
   if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest: raise ValueError("sample checksum mismatch")
  canonical="".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)).encode("ascii")
  data=load_dataset(root/"lpn_samples",expected_ciphertexts)
 analyzer=analyzer or pathlib.Path(__file__)
 return data,{"analyzer_sha256":hashlib.sha256(analyzer.read_bytes()).hexdigest(),"challenge_commit":commit,"challenge_repository":identity,
  "dataset_sha256":hashlib.sha256(canonical).hexdigest(),"files":len(hashes),"manifest_sha256":hashlib.sha256(manifest).hexdigest(),"source_mode":"validated-git-archive"}

def _hex(value:object,n:int,label:str)->str:
 if not isinstance(value,str) or len(value)!=n or re.fullmatch(r"[0-9a-f]+",value) is None: raise ValueError(f"invalid {label}")
 return value

def load_dataset(root:pathlib.Path,expected_ciphertexts:int=22)->list[Sample]:
 paths=sorted(root.glob("*.jsonl"))
 if len(paths)!=2*expected_ciphertexts: raise ValueError(f"expected {2*expected_ciphertexts} files")
 out=[]; seen=set(); common=None
 for path in paths:
  match=NAME.fullmatch(path.name)
  if not match: raise ValueError("unexpected filename")
  fc,fl=map(int,match.groups())
  with path.open("r",encoding="ascii",newline="") as fh:
   try: header=json.loads(fh.readline())
   except Exception as ex: raise ValueError("invalid header JSON") from ex
   if not isinstance(header,dict) or set(header)!=HEADER_KEYS: raise ValueError("invalid header schema")
   if header["format"]!=FORMAT or header["cipher_index"]!=fc or header["layer_id"]!=fl: raise ValueError("header identity mismatch")
   if header["slot"]!=0 or header["dom"]!="pvac.prf.r.1" or header["tau_num"]!=1 or header["tau_den"]!=8: raise ValueError("unexpected fixed metadata")
   n,t,w=header["n"],header["t"],header["row_words"]
   if not all(type(v) is int and v>0 for v in (n,t,w)) or w*64!=n: raise ValueError("invalid dimensions")
   _hex(header["nonce_lo_hex"],16,"nonce"); _hex(header["nonce_hi_hex"],16,"nonce"); _hex(header["public_T_hex"],32,"public_T")
   if type(header["seed_ztag"]) is not int or not 0<=header["seed_ztag"]<2**64: raise ValueError("invalid seed_ztag")
   dims=(n,t,w)
   if common is None: common=dims
   elif dims!=common: raise ValueError("inconsistent dimensions")
   rows=[]
   for expected,line in enumerate(fh):
    try: row=json.loads(line)
    except Exception as ex: raise ValueError("invalid row JSON") from ex
    if not isinstance(row,dict) or set(row)!=ROW_KEYS: raise ValueError("invalid row schema")
    if row["i"]!=expected: raise ValueError("row index mismatch")
    if type(row["y"]) is not int or row["y"] not in (0,1): raise ValueError("invalid y")
    a=_hex(row["a"],w*16,"row a")
    rows.append((expected,row["y"],int.from_bytes(bytes.fromhex(a),"little")))
   if len(rows)!=t: raise ValueError("row count mismatch")
  key=(fc,fl)
  if key in seen: raise ValueError("duplicate file identity")
  seen.add(key); out.append(Sample(fc,fl,n,tuple(rows)))
 if seen!={(c,l) for c in range(expected_ciphertexts) for l in range(2)}: raise ValueError("incomplete ciphertext/layer grid")
 return sorted(out,key=lambda x:(x.cipher,x.layer))

BIT_TRANSFORMS=("identity","global_reversal","per_byte_reversal","global_and_per_byte_reversal")
_REVERSE_BYTE=bytes(int(f"{i:08b}"[::-1],2) for i in range(256))
def bit_transforms(value:int,n:int)->dict[str,int]:
 if n%8: raise ValueError("bit width must be byte aligned")
 raw=value.to_bytes(n//8,"little")
 per=bytes(_REVERSE_BYTE[x] for x in raw)
 return {"identity":value,"global_reversal":int.from_bytes(per[::-1],"little"),
         "per_byte_reversal":int.from_bytes(per,"little"),
         "global_and_per_byte_reversal":int.from_bytes(raw[::-1],"little")}

def holm_adjust(pvalues:list[float])->list[float]:
 order=sorted(range(len(pvalues)),key=pvalues.__getitem__); out=[1.0]*len(order); running=0.0
 for rank,idx in enumerate(order):
  running=max(running,(len(order)-rank)*pvalues[idx]); out[idx]=min(1.0,running)
 return out

def compact_json(value:object)->str: return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)
def _corr(a,b)->float:
 a=np.asarray(a,dtype=float); b=np.asarray(b,dtype=float); d=float(np.linalg.norm(a)*np.linalg.norm(b)); return 0.0 if d==0 else float(a@b/d)
def fft_shift_correlations(a,b,antiperiodic:bool=False)->np.ndarray:
 a=np.asarray(a,dtype=float); b=np.asarray(b,dtype=float)
 if a.ndim!=1 or a.shape!=b.shape or not len(a): raise ValueError("equal nonempty vectors required")
 d=float(np.linalg.norm(a)*np.linalg.norm(b))
 if d==0:return np.zeros(len(a))
 if antiperiodic:
  aa=np.concatenate((a,np.zeros(len(a)))); bb=np.concatenate((b,-b))
  return np.fft.ifft(np.conj(np.fft.fft(aa))*np.fft.fft(bb)).real[:len(a)]/d
 return np.fft.ifft(np.conj(np.fft.fft(a))*np.fft.fft(b)).real/d
def _autocorr(x,lags:tuple[int,...])->list[float]: return [_corr(x[:-k],x[k:]) for k in lags]
def _spectral_ratio(x)->float:
 x=np.asarray(x,dtype=float); n=len(x)
 periodic=float(np.max(np.abs(np.fft.fft(x))))
 anti=float(np.max(np.abs(np.fft.fft(x*np.exp(-1j*np.pi*np.arange(n)/n)))))
 return anti/(periodic+1e-30)
def _p(obs:float,null:list[float])->float: return (1+sum(x>=obs-1e-15 for x in null))/(len(null)+1)
def permuted_mobius(grid:np.ndarray,perm:list[int],flip:list[int])->np.ndarray:
 forward=[grid[perm[c],flip[c]] for c in range(len(perm))]
 reverse=[grid[perm[c],1-flip[c]] for c in reversed(range(len(perm)))]
 return np.concatenate((forward,reverse)).reshape(-1)

def run_battery(data:list[Sample],lags:tuple[int,...]=(1,2,4,8,16),row_subset:Iterable[int]=range(256),trials:int=199,seed:int=20260711,provenance:dict|None=None)->dict:
 by={(s.cipher,s.layer):s for s in data}; width=max(s.cipher for s in data)+1; t=len(data[0].rows); n=data[0].n
 if set(by)!={(c,l) for c in range(width) for l in range(2)}: raise ValueError("nonrectangular data")
 subset=tuple(row_subset)
 if not subset or len(set(subset))!=len(subset) or min(subset)<0 or max(subset)>=t: raise ValueError("invalid row subset")
 if any(k<=0 or k>=2*width*t for k in lags): raise ValueError("invalid lag")
 y=np.asarray([[[2*r[1]-1 for r in by[c,l].rows] for l in range(2)] for c in range(width)],dtype=float)
 weights=np.asarray([[[r[2].bit_count() for r in by[c,l].rows] for l in range(2)] for c in range(width)],dtype=float)
 y-=np.mean(y); weights-=np.mean(weights)
 cyl_y=y.reshape(-1); mob_y=np.concatenate((y[:,0].reshape(-1),y[::-1,1].reshape(-1)))
 cyl_w=weights.reshape(-1); mob_w=np.concatenate((weights[:,0].reshape(-1),weights[::-1,1].reshape(-1)))
 observed=[max(abs(a-b) for a,b in zip(_autocorr(mob_y,lags),_autocorr(cyl_y,lags))),
           max(abs(a-b) for a,b in zip(_autocorr(mob_w,lags),_autocorr(cyl_w,lags))),
           abs(_spectral_ratio(mob_y)-_spectral_ratio(cyl_y))]
 seam_pairs=np.empty((2,width,width,t),dtype=np.float32)
 for anti in (0,1):
  for a in range(width):
   for b in range(width): seam_pairs[anti,a,b]=np.abs(fft_shift_correlations(y[a,0],y[b,1],bool(anti)))
 def seam_scan(mapping:list[int])->float:
  best=0.0; left=np.arange(width)
  for s in range(width):
   targets=np.asarray([mapping[(c+s)%width] for c in range(width)],dtype=np.intp)
   for anti in (0,1): best=max(best,float(np.max(np.mean(seam_pairs[anti,left,targets],axis=0))))
  return best
 observed.append(seam_scan(list(range(width))))
 rows=[[[by[c,l].rows[i][2] for i in subset] for l in range(2)] for c in range(width)]
 transformed=[[[bit_transforms(v,n) for v in rows[c][l]] for l in range(2)] for c in range(width)]
 def distance_scan(mapping:list[int])->tuple[int,int]:
  lo=comp=n
  for s in range(width):
   for c in range(width):
    for i,a in enumerate(rows[c][0]):
     for name in BIT_TRANSFORMS:
      d=(a^transformed[mapping[(c+s)%width]][1][i][name]).bit_count()
      lo=min(lo,d); comp=min(comp,n-d)
  return lo,comp
 d,dc=distance_scan(list(range(width))); observed.extend((float(d),float(dc)))
 null=[[] for _ in observed]; rng=random.Random(seed); base=list(range(width))
 for _ in range(trials):
  perm=base.copy(); rng.shuffle(perm); flip=[rng.randrange(2) for _ in base]
  py=permuted_mobius(y,perm,flip); pw=permuted_mobius(weights,perm,flip)
  null[0].append(max(abs(a-b) for a,b in zip(_autocorr(py,lags),_autocorr(cyl_y,lags))))
  null[1].append(max(abs(a-b) for a,b in zip(_autocorr(pw,lags),_autocorr(cyl_w,lags))))
  null[2].append(abs(_spectral_ratio(py)-_spectral_ratio(cyl_y)))
  null[3].append(seam_scan(perm)); nd,ndc=distance_scan(perm); null[4].append(n-nd); null[5].append(n-ndc)
 p=[_p(x if i<4 else n-x,null[i]) for i,x in enumerate(observed)]; adj=holm_adjust(p)
 names=["twisted_y_autocorrelation","twisted_row_weight_autocorrelation","antiperiodic_spectral_concentration","fft_seam_shift_scan_y","row_map_minimum_distance","row_map_complement_cancellation"]
 tests=[{"holm_p":round(adj[i],8),"name":name,"p_plus_one":round(p[i],8),"stat":round(observed[i],8)} for i,name in enumerate(names)]
 return {"design":{"bit_transforms":list(BIT_TRANSFORMS),"ciphertexts":width,"exploratory":True,"family_maxima":True,"lags":list(lags),"orientations":2,"row_subset_count":len(subset),"seam_scan_family":2*width*t,"seed":seed,"sequence_length":2*width*t,"trials":trials},"input":{"files":len(data),"format":FORMAT,"n":n,"rows_per_file":t,"validated":True},"provenance":provenance or {},"sequences":{"cylinder":"cipher-major-layer-major-row-major","mobius_double_cover":"layer0-forward-layer1-reverse-full-rows"},"tests":tests}

def main()->None:
 root=pathlib.Path(__file__).resolve().parents[2]
 ap=argparse.ArgumentParser(); ap.add_argument("--challenge-repo",type=pathlib.Path,default=root/".deps/hfhe-challenge"); ap.add_argument("--trials",type=int,default=199); ap.add_argument("--output",type=pathlib.Path)
 ns=ap.parse_args(); data,provenance=load_challenge_dataset(ns.challenge_repo); result=run_battery(data,trials=ns.trials,provenance=provenance); text=compact_json(result)+"\n"
 if ns.output: ns.output.write_text(text)
 else: print(text,end="")
if __name__=="__main__": main()
