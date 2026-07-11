#!/usr/bin/env python3
"""Bounded deterministic exploratory benchmark; validation belongs to the main audit."""
import argparse, glob, hashlib, json, os, statistics

def rows(path, limit=None):
    with open(path, 'rt', encoding='ascii') as f:
        meta=json.loads(next(f)); yield meta, None, None
        for j,line in enumerate(f):
            if limit is not None and j>=limit: break
            x=json.loads(line); yield None, bytes.fromhex(x['a']), int(x['y'])

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('directory'); ap.add_argument('--limit-per-file',type=int,default=4096); ap.add_argument('--bucket-bits',type=int,default=16)
    a=ap.parse_args(); fs=sorted(glob.glob(os.path.join(a.directory,'*.jsonl')))
    if not fs: raise SystemExit('no samples')
    metas=[]; ones=[]; seen=set(); dup=0; pairs=0; buckets={}; dists=[]; total=0
    for p in fs:
        one=0; count=0
        for meta,row,y in rows(p,a.limit_per_file):
            if meta is not None: metas.append(meta); continue
            assert row is not None and y is not None
            total+=1; count+=1; one+=y
            h=hashlib.sha256(row).digest(); dup += h in seen; seen.add(h)
            key=int.from_bytes(row[:8],'little') & ((1<<a.bucket_bits)-1)
            old=buckets.get(key)
            if old is None: buckets[key]=(row,y)
            else:
                pairs+=1
                if len(dists)<10000: dists.append(sum((x^z).bit_count() for x,z in zip(row,old[0])))
        ones.append((os.path.basename(p),one,count))
    out={'files':len(fs),'rows_scanned':total,'n_values':sorted({m['n'] for m in metas}),'t_values':sorted({m['t'] for m in metas}),'tau':sorted({(m['tau_num'],m['tau_den']) for m in metas}),'distinct_seed_tuples':len({(m['seed_ztag'],m['nonce_lo_hex'],m['nonce_hi_hex']) for m in metas}),'distinct_public_T':len({m['public_T_hex'] for m in metas}),'y_ones':sum(x[1] for x in ones),'y_fraction':sum(x[1] for x in ones)/total,'duplicate_A_sha256':dup,'bucket_bits':a.bucket_bits,'occupied_buckets':len(buckets),'same_bucket_pair_events':pairs,'xor_weight_mean_first_10000':statistics.mean(dists) if dists else None,'xor_weight_sd_first_10000':statistics.pstdev(dists) if dists else None}
    print(json.dumps(out,indent=2,sort_keys=True))
if __name__=='__main__': main()
