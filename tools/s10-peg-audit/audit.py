#!/usr/bin/env python3
"""Fail-closed, reproducible §10 cross-generation peg audit."""
from __future__ import annotations
import argparse, hashlib, io, json, math, os, pathlib, platform, random, re, subprocess, sys, tarfile, tempfile
from typing import Any

ANALYZER_VERSION = "s10-peg-audit/2"
CHALLENGE_ORIGIN = "octra-labs/hfhe-challenge"
PVAC_ORIGIN = "octra-labs/pvac_hfhe_cpp"
CHALLENGE_COMMIT = "0d08e9622921e5930175a660df0061a65548972f"
PVAC_COMMIT = "071b0e909c119de815e284b347c4bd979cb59ef3"
PEGS = ("08bf879dd9e9aff094e4106ee5d86dde9de12742", "e4645c97712542c875b7d2d8d53ac9b78b61af3f", "88a72b703f4cdd26b5fe6b3249850c2cbcef3b43")
SEED = 337
EXPECTED_COUNTS = ((18,531),(18,531),(44,1829))
EXPECTED_ARTIFACT_SHA256 = (
    {"pk":"ad5f2ecab6d71ffaaf1e363ed3b6aefc7ac1de4156a6189f8ff9ee720305a865","bundle":"8f38ed7706cca15fa5208de905cf3ee4456fafc3c72068d26ea46ac7b6fa3300"},
    {"pk":"2ebc2a258a291ad2136926c1b5f5a787a37a4499e6bdad492d9a5c3362cfc003","bundle":"1f48fae52859e3f21011a565f40348e21b4ed3aaa07b1b404d58a4fc6c0456d4"},
    {"pk":"1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410","bundle":"5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab"},
)
COMPILE_FLAGS = ("-std=c++17","-O2","-Wall","-Wextra","-Werror","-maes","-msse4.1","-mpclmul")
PAIR_IDS = {(0,1),(0,2),(1,2)}
COLLISIONS = ("exact_zero","same_coordinate_collisions","public_sum_collisions","quotient_collisions","wrapped_ratio_collisions","normalized_collisions")
class ValidationError(RuntimeError): pass

def _run(args:list[str], cwd:pathlib.Path|None=None, text:bool=True, input:bytes|None=None):
    return subprocess.run(args,cwd=cwd,check=True,capture_output=True,text=text,input=input)

def normalize_github_origin(value:str)->str:
    for p in (r"git@github\.com:([^/]+/[^/]+?)(?:\.git)?$",r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",r"ssh://git@github\.com/([^/]+/[^/]+?)(?:\.git)?/?$"):
        m=re.fullmatch(p,value.strip())
        if m:return m.group(1).lower()
    raise ValueError("origin is not a normalized GitHub repository URL")

def validate_repo(repo:pathlib.Path, expected_origin:str, commit:str)->str:
    try:
        got=normalize_github_origin(_run(["git","-C",str(repo),"remote","get-url","origin"]).stdout.strip())
        if got != expected_origin: raise ValidationError(f"origin mismatch: expected {expected_origin}")
        resolved=_run(["git","-C",str(repo),"rev-parse","--verify",f"{commit}^{{commit}}"]).stdout.strip()
        typ=_run(["git","-C",str(repo),"cat-file","-t",commit]).stdout.strip()
    except (subprocess.CalledProcessError,ValueError) as e: raise ValidationError(f"repository validation failed for {expected_origin}") from e
    if resolved != commit or typ != "commit": raise ValidationError(f"not the exact commit object: {commit}")
    return resolved

def git_blob(repo:pathlib.Path, commit:str, member:str)->str:
    try:return _run(["git","-C",str(repo),"rev-parse","--verify",f"{commit}:{member}"]).stdout.strip()
    except subprocess.CalledProcessError as e: raise ValidationError(f"missing pinned source member: {member}") from e

def safe_extract_tar(data:bytes,dest:pathlib.Path)->None:
    dest=dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data),mode="r:*") as tf:
        for m in tf.getmembers():
            if m.issym() or m.islnk() or m.isdev(): raise ValidationError("archive contains link/device")
            target=(dest/m.name).resolve()
            if target != dest and dest not in target.parents: raise ValidationError("archive path traversal")
        tf.extractall(dest,filter="data")

def archive_tree(repo:pathlib.Path,commit:str,pathspec:str,dest:pathlib.Path,prefix:str="") -> None:
    cmd=["git","-C",str(repo),"archive","--format=tar"]
    if prefix:cmd += [f"--prefix={prefix.rstrip('/')}/"]
    cmd += [commit,pathspec]
    try:data=_run(cmd,text=False).stdout
    except subprocess.CalledProcessError as e: raise ValidationError(f"cannot archive {commit}:{pathspec}") from e
    safe_extract_tar(data,dest)

def h_agreement_baseline(rows:int,low_weight:int,high_weight:int)->float:
    p=((low_weight+high_weight)/2)/rows; return 1-2*p+2*p*p

def conditional_h_agreement(a:list[int],b:list[int],rows:int)->float:
    if not a or len(a)!=len(b): raise ValidationError("H weight vectors must be nonempty and equal")
    return sum(1-x/rows-y/rows+2*x*y/(rows*rows) for x,y in zip(a,b))/len(a)

def conditional_h_agreement_from_moments(hist_a:dict,hist_b:dict,cross_product_sum:int,columns:int,rows:int)->float:
    if columns<=0 or rows<=0 or sum(hist_a.values())!=columns or sum(hist_b.values())!=columns or cross_product_sum<0:
        raise ValidationError("invalid realized H weight moments")
    sum_a=sum(int(weight)*count for weight,count in hist_a.items())
    sum_b=sum(int(weight)*count for weight,count in hist_b.items())
    return 1-sum_a/(columns*rows)-sum_b/(columns*rows)+2*cross_product_sum/(columns*rows*rows)

def _quantiles(values:list[int|float])->dict[str,float]:
    if not values: raise ValidationError("summary vector is empty")
    d=sorted(values); q=lambda p:float(d[math.floor(p*(len(d)-1))])
    return {"min":float(d[0]),"q05":q(.05),"median":q(.5),"q95":q(.95),"max":float(d[-1]),"mean":sum(d)/len(d)}

def simulate_nearest_null(bits:int,targets:int,queries:int,seed:int,trials:int=64)->dict[str,Any]:
    if min(bits,targets,queries,trials)<1: raise ValidationError("invalid nearest-null dimensions")
    rng=random.Random(seed); nq=min(queries,64); means=[]; pooled=[]
    for _ in range(trials):
        v=[min(rng.getrandbits(bits).bit_count() for _ in range(targets)) for _ in range(nq)]; pooled+=v; means.append(sum(v)/nq)
    s=_quantiles(pooled)
    return {"model":"minimum_of_m_independent_binomial_descriptive","bits":bits,"targets_m":targets,"observed_queries":queries,"simulated_queries_per_trial":nq,"trials":trials,"seed":seed,"pooled_nearest_summary":s,"trial_mean_summary":_quantiles(means),"mean":s["mean"]}

def commitment_permutation_control(a_hex:list[str],b_hex:list[str],seed:int,trials:int=50_000)->dict[str,Any]:
    if not a_hex or not b_hex: raise ValidationError("commitment groups empty")
    vals=[int(x,16) for x in a_hex+b_hex]; na=len(a_hex)
    def stat(ix):
        a=[vals[i] for i in ix[:na]];b=[vals[i] for i in ix[na:]]
        an=[min((x^y).bit_count() for y in b) for x in a];bn=[min((y^x).bit_count() for x in a) for y in b]
        return (sum(an)/len(an)+sum(bn)/len(bn))/2,min(an+bn)
    ix=list(range(len(vals))); obs=stat(ix);rng=random.Random(seed);lm=ln=0;means=[]
    for _ in range(trials):
        rng.shuffle(ix); cur=stat(ix); means.append(cur[0]);lm+=cur[0]<=obs[0];ln+=cur[1]<=obs[1]
    return {"model":"50,000-trial Monte Carlo fixed-size label-permutation test (inferential)" if trials==50_000 else "Monte Carlo fixed-size label-permutation test (inferential)","seed":seed,"trials":trials,"p_value_estimator":"plus-one: (extreme + 1) / (trials + 1)","p_value_resolution":1/(trials+1),"observed_symmetric_nearest_mean":obs[0],"observed_closest_distance":obs[1],"one_sided_p_low_mean":(lm+1)/(trials+1),"one_sided_p_low_min":(ln+1)/(trials+1),"null_trial_mean_summary":_quantiles(means)}

def _sha256(p:pathlib.Path)->str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for block in iter(lambda:f.read(1<<20),b""):h.update(block)
    return h.hexdigest()

def analyzer_source_hashes()->dict[str,str]:
    here=pathlib.Path(__file__).resolve().parent
    return {name:_sha256(here/name) for name in ("audit.py","deep_corr.cpp")}

def compiler_provenance(cxx:str)->dict[str,Any]:
    resolved=pathlib.Path(_run(["which",cxx]).stdout.strip()).resolve()
    return {"executable":str(resolved),"identity":_run([str(resolved),"--version"]).stdout.splitlines()[0],
            "target":_run([str(resolved),"-dumpmachine"]).stdout.strip(),"flags":list(COMPILE_FLAGS),"architecture":platform.machine()}

def make_document(chronology,pairs,environment,aligned_character_scan=None,source_provenance=None):
    return {"schema_version":2,"analysis":"hfhe-v2-section-10-peg-deep-correlation","analyzer_version":ANALYZER_VERSION,
      "pins":{"challenge_origin":CHALLENGE_ORIGIN,"challenge_commit":CHALLENGE_COMMIT,"pvac_origin":PVAC_ORIGIN,"pvac_commit":PVAC_COMMIT,"pegs":list(PEGS)},
      "source_provenance":source_provenance or {},"simulation":{"fixed_seed":SEED,"nearest_controls":"descriptive only; no p-values","commitment_permutation":"50,000-trial Monte Carlo label-permutation test; plus-one p-value estimator; resolution 1/50,001"},
      "chronology":chronology,"pairs":pairs,"environment":environment,"aligned_character_scan":aligned_character_scan,
      "multiplicity":{"pair_comparisons":3,"bonferroni_alpha":0.0167,"commitment_p_below_threshold":0},
      "interpretation":{"partial_nonce_reuse_detected":False,"exploitable_reuse_evidence":False,"order_337_alignment_is_public_coordinate_normalization":True,"overall":"negative: no evidence of exploitable cross-generation reuse"}}

def validate_document(d:dict)->None:
    if d.get("schema_version")!=2 or d.get("analyzer_version")!=ANALYZER_VERSION: raise ValidationError("wrong schema/analyzer version")
    pins=d.get("pins",{})
    expected={"challenge_origin":CHALLENGE_ORIGIN,"challenge_commit":CHALLENGE_COMMIT,"pvac_origin":PVAC_ORIGIN,"pvac_commit":PVAC_COMMIT,"pegs":list(PEGS)}
    if pins!=expected: raise ValidationError("pins/origins/peg order differ")
    c=d.get("chronology",[])
    if len(c)!=3 or [x.get("peg") for x in c]!=list(PEGS): raise ValidationError("chronology/peg order invalid")
    for i,x in enumerate(c):
        co=x.get("counts",{}); expected_nonce,expected_edges=EXPECTED_COUNTS[i]
        if (co.get("base_nonces"),co.get("pcs"),co.get("edges"),co.get("h_columns"),co.get("ubk_permutation"))!=(expected_nonce,expected_nonce,expected_edges,16384,8192): raise ValidationError("unexpected object counts")
        if x.get("parameters")!={"B":337,"m_bits":8192,"n":16384}: raise ValidationError("unexpected parameters")
        if x.get("artifact_sha256")!=EXPECTED_ARTIFACT_SHA256[i]: raise ValidationError("artifact SHA256 differs from reviewed peg")
        tags=x.get("canonical_tags",{})
        if tags!={"recomputed":expected_nonce,"verified":expected_nonce,"mismatches":0}: raise ValidationError("canonical-tag recomputation evidence invalid")
    provenance=d.get("source_provenance",{})
    if provenance.get("analyzer_sources")!=analyzer_source_hashes(): raise ValidationError("analyzer source SHA256 mismatch")
    compiler=d.get("environment",{}).get("compiler",{})
    if set(compiler)!={"executable","identity","target","flags","architecture"} or compiler.get("flags")!=list(COMPILE_FLAGS): raise ValidationError("compiler provenance incomplete")
    if not all(isinstance(compiler.get(k),str) and compiler[k] for k in ("executable","identity","target","architecture")): raise ValidationError("compiler provenance values invalid")
    pairs=d.get("pairs",[])
    if len(pairs)!=3 or {tuple(x.get("peg_indices",[])) for x in pairs}!=PAIR_IDS: raise ValidationError("pair coverage invalid")
    for p in pairs:
        if p.get("partial_nonce_reuse",{}).get("detected") or any(p.get("partial_nonce_reuse",{}).get(k)!=0 for k in ("lo64","hi64","prefix32","suffix32")): raise ValidationError("partial nonce reuse")
        ev=p.get("exact_intersections",{})
        if set(ev)!={"seed","nonce","pc","sigma","weight"} or any(ev.values()): raise ValidationError("exact intersection evidence missing/nonzero")
        if p.get("ztag_mismatches")!=0: raise ValidationError("ztag mismatch")
        h=p.get("h_columns",{})
        if h.get("columns")!=16384 or not h.get("realized_weight_histograms") or "conditional_expected_agreement" not in h or "unconditional_model_reference" not in h: raise ValidationError("H evidence incomplete")
        hist_a,hist_b=h["realized_weight_histograms"]
        cross_sum=h.get("realized_weight_cross_product_sum")
        if not isinstance(cross_sum,int): raise ValidationError("realized H cross-moment missing")
        expected_h=conditional_h_agreement_from_moments(hist_a,hist_b,cross_sum,16384,8192)
        if abs(h["conditional_expected_agreement"]-expected_h)>1e-15: raise ValidationError("conditional H expectation does not match realized moments")
        if p.get("subgroup",{}).get("order")!=337: raise ValidationError("subgroup invalid")
        if p.get("interpretation",{}).get("nearest_controls")!="descriptive_only": raise ValidationError("nearest controls not descriptive")
    scan=d.get("aligned_character_scan",{})
    if [scan.get(k) for k in ("generations","ciphertexts","layers","character_values")] != [3,40,80,26960]: raise ValidationError("scan dimensions invalid")
    maps=scan.get("basis_maps")
    if not isinstance(maps,list) or len(maps)!=3 or any(not isinstance(x,int) or not 1<=x<337 or math.gcd(x,337)!=1 for x in maps): raise ValidationError("basis maps invalid")
    if any(scan.get(k)!=0 for k in COLLISIONS): raise ValidationError("collision detected")
    if d.get("multiplicity")!={"pair_comparisons":3,"bonferroni_alpha":0.0167,"commitment_p_below_threshold":0}: raise ValidationError("multiplicity statement invalid")
    encoded=json.dumps(d,sort_keys=True)
    forbidden=("secret.ct","pk.bin","PRIVATE KEY","mnemonic","/tmp/",str(pathlib.Path.home()),"raw_distances","raw_trial")
    if any(x in encoded for x in forbidden): raise ValidationError("secret/path/raw marker in output")

def _extract(repo,peg,member,dest):
    with dest.open("wb") as out:r=subprocess.run(["git","-C",str(repo),"show",f"{peg}:{member}"],stdout=out,stderr=subprocess.PIPE)
    if r.returncode: raise ValidationError(f"required artifact absent at peg {peg}")

def _compile(source,binary,headers,cxx):
    subprocess.run([cxx,*COMPILE_FLAGS,"-I",str(headers/"include"),"-I",str(headers/"source"),str(source),"-o",str(binary)],check=True)

def run(args):
    challenge,pvac=args.challenge_repo.resolve(),args.pvac_repo.resolve()
    validate_repo(challenge,CHALLENGE_ORIGIN,CHALLENGE_COMMIT);validate_repo(pvac,PVAC_ORIGIN,PVAC_COMMIT)
    for peg in PEGS:validate_repo(challenge,CHALLENGE_ORIGIN,peg)
    pvac_blob=git_blob(pvac,PVAC_COMMIT,"include/pvac/pvac.hpp"); challenge_blob=git_blob(challenge,CHALLENGE_COMMIT,"source/pvac_artifact_serialize.hpp")
    with tempfile.TemporaryDirectory(prefix="s10-peg-audit-") as td:
        root=pathlib.Path(td); headers=root/"headers";headers.mkdir();archive_tree(pvac,PVAC_COMMIT,"include",headers);archive_tree(challenge,CHALLENGE_COMMIT,"source/pvac_artifact_serialize.hpp",headers)
        dirs=[];chron=[]
        for i,peg in enumerate(PEGS):
            p=root/f"peg-{i}";p.mkdir();pk=p/"pk.bin";bundle=p/"secret.ct";_extract(challenge,peg,"pk.bin",pk);_extract(challenge,peg,"secret.ct",bundle)
            ts=_run(["git","-C",str(challenge),"show","-s","--format=%aI",peg]).stdout.strip()
            chron.append({"peg":peg,"timestamp":ts,"source_blobs":{"pk":git_blob(challenge,peg,"pk.bin"),"bundle":git_blob(challenge,peg,"secret.ct")},"artifact_sha256":{"pk":_sha256(pk),"bundle":_sha256(bundle)}});dirs.append(p)
        binary=root/"deep-corr"
        _compile(pathlib.Path(__file__).with_name("deep_corr.cpp"),binary,headers,args.cxx)
        try: parsed=json.loads(_run([str(binary),*map(str,dirs)]).stdout)
        except subprocess.CalledProcessError as e: raise ValidationError(e.stderr.strip() or "native analyzer failed") from e
    pc_hex=parsed.pop("pc_hex");scan=parsed.pop("aligned_character_scan")
    for x,a in zip(chron,parsed["artifacts"],strict=True):x.update(a)
    for pi,p in enumerate(parsed["pairs"]):
        ai,bi=p["peg_indices"]
        hist_a=chron[ai]["h_weight_histogram"];hist_b=chron[bi]["h_weight_histogram"]
        h_columns=p["h_columns"];columns=h_columns["columns"];cross_sum=h_columns["realized_weight_cross_product_sum"]
        h_columns["realized_weight_histograms"]=[hist_a,hist_b]
        h_columns["conditional_expected_agreement"]=conditional_h_agreement_from_moments(hist_a,hist_b,cross_sum,columns,8192)
        p["h_columns"]["unconditional_model_reference"]={"model":"independent uniform 192/193 weights","agreement":h_agreement_baseline(8192,192,193)}
        for di,n in enumerate(p["nearest"]):
            q=n.pop("query_count");n["null_distribution"]=simulate_nearest_null(n["bits"],n["targets_m"],q,SEED+pi*100+di)
        p["commitment_permutation"]=commitment_permutation_control(pc_hex[ai],pc_hex[bi],SEED+1000+pi)
        p["interpretation"]={"nearest_controls":"descriptive_only","multiple_testing_claim":"none for nearest controls","exploitable_reuse_evidence":False}
    doc=make_document(chron,parsed["pairs"],{"runtime":"deterministic-output-v1","compiler":compiler_provenance(args.cxx)},scan,{"pvac_header_commit":PVAC_COMMIT,"pvac_root_header_blob":pvac_blob,"challenge_header_commit":CHALLENGE_COMMIT,"challenge_serializer_blob":challenge_blob,"analyzer_sources":analyzer_source_hashes(),"build":"git archive only; safe extracted"})
    validate_document(doc);return doc

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--challenge-repo",type=pathlib.Path,required=True);ap.add_argument("--pvac-repo",type=pathlib.Path,required=True);ap.add_argument("--output",type=pathlib.Path,required=True);ap.add_argument("--check-output",action="store_true");ap.add_argument("--cxx",default=os.environ.get("CXX","g++"));args=ap.parse_args()
    try:
        doc=run(args);render=json.dumps(doc,indent=2,sort_keys=True)+"\n"
        if args.check_output:
            if not args.output.exists() or args.output.read_text()!=render: raise ValidationError("output differs from exact regenerated document")
        else:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(render)
    except (ValidationError,subprocess.CalledProcessError,OSError,json.JSONDecodeError,KeyError,ValueError) as e:print(f"audit failed closed: {e}",file=sys.stderr);return 2
    return 0
if __name__=="__main__":raise SystemExit(main())
