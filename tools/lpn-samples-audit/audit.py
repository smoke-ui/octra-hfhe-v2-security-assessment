#!/usr/bin/env python3
"""Reproducible, fail-closed audit of OCTRA's pinned LPN JSONL release."""
from __future__ import annotations
import argparse, hashlib, io, json, math, os, pathlib, platform, re, sqlite3, subprocess, sys, tarfile, tempfile
from typing import Any

VERSION="lpn-samples-audit/1"
CHALLENGE_ORIGIN="octra-labs/hfhe-challenge"
PVAC_ORIGIN="octra-labs/pvac_hfhe_cpp"
CHALLENGE_COMMIT="d9d29d505e2840c0028d7a91a2a8ba59e163b9a4"
CLARIFICATION_COMMIT="019380c97543620091409b0fbf73a8a773a9a0da"
PVAC_COMMIT="071b0e909c119de815e284b347c4bd979cb59ef3"
FILES=44; ROWS_PER_FILE=16384; N=4096; TOTAL_ROWS=720896
EXPECTED_A_ONES=1476351832; EXPECTED_Y_ONES=360224
EXPECTED_CHALLENGE_BLOBS={"SHA256SUMS":"fb8bfa3a7e42a1a94056504c209f97601de937b6","lpn_samples_tree":"e8c35f4ae55384515051094a905710d4473658c3","official_verifier":"db7d1aca44e9ff4122317413c403e4f592aa2ce8"}
EXPECTED_PVAC_INCLUDE_TREE="9bdfef2aa7c111c4117c25f7c1855f63547a1460"
META_KEYS={"format","cipher_index","layer_id","slot","dom","n","t","tau_num","tau_den","row_words","seed_ztag","nonce_lo_hex","nonce_hi_hex","public_T_hex"}
ROW_KEYS={"i","y","a"}
NAME_RE=re.compile(r"ct(\d{2})_l([01])_s(0)_pvac_prf_r_1\.jsonl")
HEX16=re.compile(r"[0-9a-f]{16}"); HEX32=re.compile(r"[0-9a-f]{32}"); HEXROW=re.compile(r"[0-9a-f]{1024}")
FLAGS=("-std=c++17","-O2","-Wall","-Wextra","-Werror","-maes","-msse4.1","-mpclmul")
class ValidationError(RuntimeError): pass

def run(cmd:list[str], *, cwd:pathlib.Path|None=None, data:bytes|None=None, text=True):
    return subprocess.run(cmd,cwd=cwd,input=data,capture_output=True,text=text,check=True)

def normalize_origin(s:str)->str:
    patterns=(r"git@github\.com:([^/]+/[^/]+?)(?:\.git)?",r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?",r"ssh://git@github\.com/([^/]+/[^/]+?)(?:\.git)?/?")
    for p in patterns:
        m=re.fullmatch(p,s.strip())
        if m:return m.group(1).lower()
    raise ValidationError("origin is not an accepted normalized GitHub URL")

def validate_repo(repo:pathlib.Path, origin:str, commits:list[str])->None:
    try: got=normalize_origin(run(["git","-C",str(repo),"remote","get-url","origin"]).stdout)
    except (subprocess.CalledProcessError,ValidationError) as e: raise ValidationError(f"cannot validate repository origin for {origin}") from e
    if got!=origin: raise ValidationError(f"origin mismatch: expected {origin}, got {got}")
    for commit in commits:
        try:
            resolved=run(["git","-C",str(repo),"rev-parse","--verify",commit+"^{commit}"]).stdout.strip()
            typ=run(["git","-C",str(repo),"cat-file","-t",commit]).stdout.strip()
        except subprocess.CalledProcessError as e: raise ValidationError(f"missing exact commit {commit}") from e
        if resolved!=commit or typ!="commit": raise ValidationError(f"not exact commit object: {commit}")

def safe_extract_tar(data:bytes,dest:pathlib.Path)->None:
    root=dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data),mode="r:*") as tf:
        for m in tf.getmembers():
            if not (m.isfile() or m.isdir()) or m.issym() or m.islnk() or m.isdev(): raise ValidationError("archive has non-regular member")
            target=(root/m.name).resolve()
            if target!=root and root not in target.parents: raise ValidationError("archive path traversal")
        tf.extractall(root,filter="data")

def archive(repo:pathlib.Path,commit:str,pathspecs:list[str],dest:pathlib.Path,prefix="")->None:
    cmd=["git","-C",str(repo),"archive","--format=tar"]
    if prefix:cmd += ["--prefix="+prefix.rstrip("/")+"/"]
    cmd += [commit,*pathspecs]
    try: raw=run(cmd,text=False).stdout
    except subprocess.CalledProcessError as e: raise ValidationError("git archive failed") from e
    safe_extract_tar(raw,dest)

def sha256(path:pathlib.Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):h.update(b)
    return h.hexdigest()

def blob(repo:pathlib.Path,commit:str,member:str)->str:
    try:return run(["git","-C",str(repo),"rev-parse","--verify",f"{commit}:{member}"]).stdout.strip()
    except subprocess.CalledProcessError as e:raise ValidationError(f"missing pinned member {member}") from e

def parse_manifest(path:pathlib.Path)->dict[str,str]:
    out={}
    for line in path.read_text("ascii").splitlines():
        m=re.fullmatch(r"([0-9a-f]{64})  (lpn_samples/[^/]+\.jsonl)",line)
        if m:
            if m.group(2) in out:raise ValidationError("duplicate relevant checksum entry")
            out[m.group(2)]=m.group(1)
    if len(out)!=FILES:raise ValidationError(f"expected {FILES} relevant checksum entries")
    return out

def add_rank(pivots:dict[int,int],v:int)->None:
    while v:
        p=v.bit_length()-1
        old=pivots.get(p)
        if old is None:pivots[p]=v;return
        v^=old

def validate_meta(meta:Any,coord:tuple[int,int,int],name:str="sample")->tuple:
    if type(meta) is not dict or set(meta)!=META_KEYS:raise ValidationError(f"metadata schema: {name}")
    fixed={"format":"octra-bounty-target-seed-lpn-ay-v1","dom":"pvac.prf.r.1","n":N,"t":ROWS_PER_FILE,"tau_num":1,"tau_den":8,"row_words":64}
    if any(meta[k]!=v or type(meta[k]) is not type(v) for k,v in fixed.items()):raise ValidationError(f"metadata constants: {name}")
    if (type(meta["cipher_index"]) is not int or type(meta["layer_id"]) is not int or type(meta["slot"]) is not int or (meta["cipher_index"],meta["layer_id"],meta["slot"])!=coord):raise ValidationError(f"filename-coordinate mismatch: {name}")
    if type(meta["seed_ztag"]) is not int or not 0<=meta["seed_ztag"]<2**64:raise ValidationError("bad seed_ztag")
    if not (type(meta["nonce_lo_hex"]) is str and HEX16.fullmatch(meta["nonce_lo_hex"]) and type(meta["nonce_hi_hex"]) is str and HEX16.fullmatch(meta["nonce_hi_hex"]) and type(meta["public_T_hex"]) is str and HEX32.fullmatch(meta["public_T_hex"])):raise ValidationError("bad metadata hex")
    return (meta["seed_ztag"],meta["nonce_lo_hex"],meta["nonce_hi_hex"],meta["public_T_hex"])

def validate_row(r:Any,index:int,name:str="sample")->tuple[bytes,int]:
    if type(r) is not dict or set(r)!=ROW_KEYS or type(r["i"]) is not int or r["i"]!=index or type(r["y"]) is not int or r["y"] not in (0,1) or type(r["a"]) is not str or not HEXROW.fullmatch(r["a"]):raise ValidationError(f"row schema: {name}:{index}")
    return bytes.fromhex(r["a"]),r["y"]

def official_metadata_model(path:pathlib.Path)->tuple:
    """Model the documented verifier scope: first-line metadata only (for caveat tests)."""
    with path.open("rt",encoding="ascii") as f:meta=json.loads(next(f))
    return (meta.get("dom"),meta.get("seed_ztag"),meta.get("nonce_lo_hex"),meta.get("nonce_hi_hex"),meta.get("public_T_hex"))

def z_balance(ones:int,bits:int)->float:return (ones-bits/2)/math.sqrt(bits/4)

def audit_samples(root:pathlib.Path, manifest:dict[str,str], db:pathlib.Path)->tuple[dict,list[dict],list[dict]]:
    paths=sorted((root/"lpn_samples").glob("*.jsonl"))
    if len(paths)!=FILES:raise ValidationError("sample file count mismatch")
    expected={(ct,l,0) for ct in range(22) for l in range(2)}; coords=set(); metas=set()
    conn=sqlite3.connect(db);conn.executescript("PRAGMA journal_mode=OFF;PRAGMA synchronous=OFF;PRAGMA temp_store=FILE;PRAGMA cache_size=-65536;CREATE TABLE seen(a BLOB PRIMARY KEY,y0 INTEGER NOT NULL,y1 INTEGER NOT NULL);")
    dup_a=dup_ay=0; total_a_ones=total_y_ones=0; per=[]; metadata=[]
    for path in paths:
        rel="lpn_samples/"+path.name
        if rel not in manifest or sha256(path)!=manifest[rel]:raise ValidationError(f"checksum mismatch: {rel}")
        nm=NAME_RE.fullmatch(path.name)
        if not nm:raise ValidationError(f"invalid filename: {path.name}")
        coord=tuple(map(int,nm.groups()));coords.add(coord)
        pa={};pay={};aones=yones=count=0
        with path.open("rt",encoding="ascii",newline="") as f:
            try: meta=json.loads(next(f))
            except (StopIteration,json.JSONDecodeError) as e:raise ValidationError(f"bad metadata: {path.name}") from e
            mt=validate_meta(meta,coord,path.name)
            if mt in metas:raise ValidationError("duplicate metadata tuple")
            metas.add(mt);metadata.append({"file":path.name,"cipher_index":coord[0],"layer_id":coord[1],"slot":0,"seed_ztag":meta["seed_ztag"],"nonce_lo_hex":meta["nonce_lo_hex"],"nonce_hi_hex":meta["nonce_hi_hex"],"public_T_hex":meta["public_T_hex"]})
            for line in f:
                try:r=json.loads(line)
                except json.JSONDecodeError as e:raise ValidationError(f"row JSON: {path.name}:{count}") from e
                a,y=validate_row(r,count,path.name); av=int.from_bytes(a,"little")
                add_rank(pa,av);add_rank(pay,av|(y<<N));aones+=av.bit_count();yones+=y
                cur=conn.execute("SELECT y0,y1 FROM seen WHERE a=?",(a,)).fetchone()
                if cur is None:conn.execute("INSERT INTO seen VALUES(?,?,?)",(a,int(y==0),int(y==1)))
                else:
                    dup_a+=1
                    if cur[y]:dup_ay+=1
                    else:conn.execute("UPDATE seen SET y0=?,y1=? WHERE a=?",(int(cur[0] or y==0),int(cur[1] or y==1),a))
                count+=1
        if count!=ROWS_PER_FILE:raise ValidationError(f"row count: {path.name}")
        if len(pa)!=N or len(pay)!=N+1:raise ValidationError(f"rank deficiency: {path.name}")
        total_a_ones+=aones;total_y_ones+=yones
        per.append({"file":path.name,"rows":count,"rank_A":len(pa),"rank_Augmented":len(pay),"A_ones":aones,"y_ones":yones})
        conn.commit()
    conn.close()
    if coords!=expected:raise ValidationError("coordinate coverage mismatch")
    if sum(x["rows"] for x in per)!=TOTAL_ROWS:raise ValidationError("global row count mismatch")
    abits=TOTAL_ROWS*N
    summary={"files":FILES,"rows":TOTAL_ROWS,"A_bits":abits,"A_ones":total_a_ones,"A_one_fraction":total_a_ones/abits,"A_balance_z":z_balance(total_a_ones,abits),"y_ones":total_y_ones,"y_one_fraction":total_y_ones/TOTAL_ROWS,"y_balance_z":z_balance(total_y_ones,TOTAL_ROWS),"duplicate_A_rows_exact":dup_a,"duplicate_A_y_rows_exact":dup_ay,"metadata_tuples_unique":len(metas),"rank_A_min":min(x["rank_A"] for x in per),"rank_A_max":max(x["rank_A"] for x in per),"rank_Augmented_min":min(x["rank_Augmented"] for x in per),"rank_Augmented_max":max(x["rank_Augmented"] for x in per)}
    return summary,per,metadata

def compiler(cxx:str)->dict[str,Any]:
    exe=pathlib.Path(run(["which",cxx]).stdout.strip()).resolve()
    return {"executable_name":exe.name,"executable_sha256":sha256(exe),"identity":run([str(exe),"--version"]).stdout.splitlines()[0],"target":run([str(exe),"-dumpmachine"]).stdout.strip(),"architecture":platform.machine(),"flags":list(FLAGS)}

def compile_verifier(src:pathlib.Path,headers:pathlib.Path,out:pathlib.Path,cxx:str)->None:
    run([cxx,*FLAGS,"-I",str(headers/"include"),"-I",str(src.parent.parent),str(src),"-o",str(out)])

def verify_bindings(binary:pathlib.Path,pk:pathlib.Path,bundle:pathlib.Path,samples:pathlib.Path)->int:
    n=0
    for p in sorted(samples.glob("*.jsonl")):
        try:r=run([str(binary),str(pk),str(bundle),str(p)])
        except subprocess.CalledProcessError as e:raise ValidationError(f"official metadata verifier rejected {p.name}") from e
        if r.stdout.strip()!="binding = 1":raise ValidationError("unexpected verifier output")
        n+=1
    return n

def source_hashes()->dict[str,str]:
    here=pathlib.Path(__file__).resolve().parent
    return {x:sha256(here/x) for x in ("audit.py","test_audit.py","README.md")}

def validate_document(d:dict)->None:
    if d.get("schema_version")!=1 or d.get("analysis")!="octra-lpn-samples-audit" or d.get("analyzer_version")!=VERSION:raise ValidationError("document identity invalid")
    pins=d.get("pins",{});expected={"challenge_origin":CHALLENGE_ORIGIN,"challenge_release_commit":CHALLENGE_COMMIT,"challenge_clarification_commit":CLARIFICATION_COMMIT,"pvac_origin":PVAC_ORIGIN,"pvac_commit":PVAC_COMMIT}
    if pins!=expected:raise ValidationError("document pins invalid")
    s=d.get("summary",{})
    if (s.get("files"),s.get("rows"),s.get("metadata_tuples_unique"),s.get("rank_A_min"),s.get("rank_A_max"),s.get("rank_Augmented_min"),s.get("rank_Augmented_max"))!=(FILES,TOTAL_ROWS,FILES,N,N,N+1,N+1):raise ValidationError("summary dimensions invalid")
    if (s.get("A_bits"),s.get("A_ones"),s.get("y_ones"))!=(TOTAL_ROWS*N,EXPECTED_A_ONES,EXPECTED_Y_ONES):raise ValidationError("reviewed aggregate evidence differs")
    if s.get("A_one_fraction")!=EXPECTED_A_ONES/(TOTAL_ROWS*N) or s.get("A_balance_z")!=z_balance(EXPECTED_A_ONES,TOTAL_ROWS*N) or s.get("y_one_fraction")!=EXPECTED_Y_ONES/TOTAL_ROWS or s.get("y_balance_z")!=z_balance(EXPECTED_Y_ONES,TOTAL_ROWS):raise ValidationError("aggregate statistics inconsistent")
    if s.get("duplicate_A_rows_exact")!=0 or s.get("duplicate_A_y_rows_exact")!=0:raise ValidationError("unexpected duplicate rows")
    pf=d.get("per_file",[])
    expected_names={f"ct{ct:02d}_l{layer}_s0_pvac_prf_r_1.jsonl" for ct in range(22) for layer in range(2)}
    if len(pf)!=FILES or {x.get("file") for x in pf}!=expected_names or any(x.get("rows")!=ROWS_PER_FILE or x.get("rank_A")!=N or x.get("rank_Augmented")!=N+1 for x in pf):raise ValidationError("per-file evidence invalid")
    if sum(x.get("A_ones",-1) for x in pf)!=EXPECTED_A_ONES or sum(x.get("y_ones",-1) for x in pf)!=EXPECTED_Y_ONES:raise ValidationError("per-file aggregates inconsistent")
    provenance=d.get("provenance",{})
    if provenance.get("source_hashes")!=source_hashes() or provenance.get("challenge_blobs")!=EXPECTED_CHALLENGE_BLOBS or provenance.get("pvac_include_tree")!=EXPECTED_PVAC_INCLUDE_TREE or provenance.get("input_policy")!="immutable git archive objects only; no working-tree inputs":raise ValidationError("source/input provenance invalid")
    compiler_info=provenance.get("compiler",{})
    if compiler_info.get("flags")!=list(FLAGS) or not all(compiler_info.get(k) for k in ("executable_name","executable_sha256","identity","target","architecture")) or not re.fullmatch(r"[0-9a-f]{64}",compiler_info.get("executable_sha256","")):raise ValidationError("compiler provenance invalid")
    b=d.get("metadata_binding",{})
    if b!={"official_verifier_passed":FILES,"scope":"metadata-only set-membership; verifier reads only the first JSONL line and cannot authenticate equation bodies"}:raise ValidationError("binding evidence/scope invalid")
    if d.get("checksums",{}).get("relevant_entries_verified")!=FILES:raise ValidationError("checksum evidence invalid")
    encoded=json.dumps(d,sort_keys=True)
    if any(x in encoded for x in ("/home/","/tmp/","raw_rows","seconds","elapsed","rows_per_second")):raise ValidationError("path/raw/timing leakage")

def execute(args)->dict:
    cr=args.challenge_repo.resolve();pr=args.pvac_repo.resolve()
    validate_repo(cr,CHALLENGE_ORIGIN,[CHALLENGE_COMMIT,CLARIFICATION_COMMIT]);validate_repo(pr,PVAC_ORIGIN,[PVAC_COMMIT])
    with tempfile.TemporaryDirectory(prefix="lpn-audit-") as td:
        root=pathlib.Path(td);challenge=root/"challenge";headers=root/"pvac";challenge.mkdir();headers.mkdir()
        archive(cr,CHALLENGE_COMMIT,["SHA256SUMS","lpn_samples","pk.bin","secret.ct","source/tools/verify_lpn_sample_binding.cpp","source/pvac_artifact_serialize.hpp"],challenge)
        archive(pr,PVAC_COMMIT,["include"],headers)
        manifest=parse_manifest(challenge/"SHA256SUMS")
        summary,per,metadata=audit_samples(challenge,manifest,root/"seen.sqlite")
        binary=root/"verify-binding";src=challenge/"source/tools/verify_lpn_sample_binding.cpp";compile_verifier(src,headers,binary,args.cxx)
        verified=verify_bindings(binary,challenge/"pk.bin",challenge/"secret.ct",challenge/"lpn_samples")
    doc={"schema_version":1,"analysis":"octra-lpn-samples-audit","analyzer_version":VERSION,"pins":{"challenge_origin":CHALLENGE_ORIGIN,"challenge_release_commit":CHALLENGE_COMMIT,"challenge_clarification_commit":CLARIFICATION_COMMIT,"pvac_origin":PVAC_ORIGIN,"pvac_commit":PVAC_COMMIT},"provenance":{"source_hashes":source_hashes(),"challenge_blobs":{"SHA256SUMS":blob(cr,CHALLENGE_COMMIT,"SHA256SUMS"),"lpn_samples_tree":blob(cr,CHALLENGE_COMMIT,"lpn_samples"),"official_verifier":blob(cr,CHALLENGE_COMMIT,"source/tools/verify_lpn_sample_binding.cpp")},"pvac_include_tree":blob(pr,PVAC_COMMIT,"include"),"compiler":compiler(args.cxx),"input_policy":"immutable git archive objects only; no working-tree inputs"},"checksums":{"manifest":"SHA256SUMS at pinned release commit","relevant_entries":FILES,"relevant_entries_verified":FILES},"schema":{"metadata_exact_keys":sorted(META_KEYS),"row_exact_keys":sorted(ROW_KEYS),"expected_files":FILES,"rows_per_file":ROWS_PER_FILE,"n":N,"row_bytes":512},"summary":summary,"per_file":per,"metadata":metadata,"metadata_binding":{"official_verifier_passed":verified,"scope":"metadata-only set-membership; verifier reads only the first JSONL line and cannot authenticate equation bodies"},"duplicate_method":"exact SQLite BLOB equality over complete 512-byte A rows; (A,y) equality checked after exact A match; no truncated-hash identity claim","interpretation":{"repository_bytes_authenticated":True,"metadata_set_membership_bound":True,"equation_bodies_bound_by_official_verifier":False}}
    validate_document(doc);return doc

def main()->int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--challenge-repo",required=True,type=pathlib.Path);p.add_argument("--pvac-repo",required=True,type=pathlib.Path);p.add_argument("--output",required=True,type=pathlib.Path);p.add_argument("--check-output",action="store_true");p.add_argument("--cxx",default=os.environ.get("CXX","g++"));a=p.parse_args()
    try:
        rendered=json.dumps(execute(a),indent=2,sort_keys=True)+"\n"
        if a.check_output:
            if not a.output.exists() or a.output.read_text("utf-8")!=rendered:raise ValidationError("output differs from exact regeneration")
        else:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(rendered,"utf-8")
    except (ValidationError,subprocess.CalledProcessError,OSError,ValueError,KeyError,json.JSONDecodeError) as e:print(f"audit failed closed: {e}",file=sys.stderr);return 2
    return 0
if __name__=="__main__":raise SystemExit(main())
