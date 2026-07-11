#!/usr/bin/env python3
import copy, importlib.util, io, json, pathlib, tarfile, tempfile, unittest
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("audit",HERE/"audit.py");a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

def meta():return {"format":"octra-bounty-target-seed-lpn-ay-v1","cipher_index":0,"layer_id":0,"slot":0,"dom":"pvac.prf.r.1","n":4096,"t":16384,"tau_num":1,"tau_den":8,"row_words":64,"seed_ztag":1,"nonce_lo_hex":"00"*8,"nonce_hi_hex":"11"*8,"public_T_hex":"22"*16}
def document():return json.loads((HERE/"results/lpn-samples.json").read_text())
class Tests(unittest.TestCase):
 def test_origins(self):
  self.assertEqual(a.normalize_origin("git@github.com:octra-labs/hfhe-challenge.git"),a.CHALLENGE_ORIGIN)
  for x in ("file:///x","https://evil.test/x","https://github.com/octra-labs/hfhe-challenge/extra"):
   with self.assertRaises(a.ValidationError):a.normalize_origin(x)
 def test_archive_traversal_and_link(self):
  for name,kind in (("../escape",None),("link","sym")):
   b=io.BytesIO()
   with tarfile.open(fileobj=b,mode="w") as t:
    i=tarfile.TarInfo(name);i.size=1
    if kind:i.type=tarfile.SYMTYPE;i.linkname="target";i.size=0
    t.addfile(i,None if kind else io.BytesIO(b"x"))
   with tempfile.TemporaryDirectory() as d:
    with self.assertRaises(a.ValidationError):a.safe_extract_tar(b.getvalue(),pathlib.Path(d))
 def test_schema_and_coordinate_mutations(self):
  m=meta();self.assertEqual(a.validate_meta(m,(0,0,0))[0],1)
  for mut in (lambda x:x.update(extra=1),lambda x:x.update(n=4095),lambda x:x.update(cipher_index=1),lambda x:x.update(nonce_lo_hex="GG"*8)):
   q=copy.deepcopy(m);mut(q)
   with self.assertRaises(a.ValidationError):a.validate_meta(q,(0,0,0))
 def test_row_mutations_and_duplicate_identity(self):
  r={"i":0,"y":1,"a":"00"*512};self.assertEqual(a.validate_row(r,0),(bytes(512),1))
  for q in ({**r,"i":1},{**r,"y":2},{**r,"a":"00"*511},{**r,"extra":0}):
   with self.assertRaises(a.ValidationError):a.validate_row(q,0)
  # Complete bytes, not truncated hashes, distinguish near-duplicates.
  self.assertNotEqual(a.validate_row(r,0)[0],a.validate_row({**r,"a":"00"*511+"01"},0)[0])
 def test_forged_body_still_passes_metadata_model_caveat(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"x";head=json.dumps(meta())+"\n"
   p.write_text(head+json.dumps({"i":0,"y":0,"a":"00"*512})+"\n") ;x=a.official_metadata_model(p)
   p.write_text(head+"arbitrary forged body\n");self.assertEqual(x,a.official_metadata_model(p))
 def test_document_validator_mutations(self):
  d=document();a.validate_document(d)
  mutations=(("summary","rows",1),("summary","A_ones",1),("summary","duplicate_A_rows_exact",1),("metadata_binding","official_verifier_passed",43),("pins","pvac_commit","0"*40))
  for section,key,value in mutations:
   q=copy.deepcopy(d);q[section][key]=value
   with self.assertRaises(a.ValidationError):a.validate_document(q)
  q=copy.deepcopy(d);q["provenance"]["source_hashes"]["audit.py"]="0"*64
  with self.assertRaises(a.ValidationError):a.validate_document(q)
 def test_rank(self):
  p={};[a.add_rank(p,x) for x in (1,2,3,4)];self.assertEqual(len(p),3)
if __name__=="__main__":unittest.main()
