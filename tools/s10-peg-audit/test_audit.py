import io, json, pathlib, subprocess, sys, tarfile, tempfile, unittest
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));import audit

class AuditTests(unittest.TestCase):
 def result(self): return json.loads((HERE/"results/s10-pegs.json").read_text())
 def test_origin_normalization(self):
  for x in ("git@github.com:octra-labs/hfhe-challenge.git","https://github.com/octra-labs/hfhe-challenge.git","ssh://git@github.com/octra-labs/hfhe-challenge"):
   self.assertEqual(audit.normalize_github_origin(x),"octra-labs/hfhe-challenge")
 def test_wrong_origins_rejected(self):
  for x in ("https://evil.test/a/b","file:///tmp/x","../x","https://github.com/a/b/extra"):
   with self.assertRaises(ValueError): audit.normalize_github_origin(x)
 def test_wrong_origin_and_missing_commit_fail_closed(self):
  with tempfile.TemporaryDirectory() as td:
   repo=pathlib.Path(td);subprocess.run(["git","init","-q",str(repo)],check=True);subprocess.run(["git","-C",str(repo),"remote","add","origin","https://github.com/attacker/x.git"],check=True)
   with self.assertRaises(audit.ValidationError):audit.validate_repo(repo,audit.CHALLENGE_ORIGIN,"0"*40)
   subprocess.run(["git","-C",str(repo),"remote","set-url","origin","https://github.com/octra-labs/hfhe-challenge.git"],check=True)
   with self.assertRaises(audit.ValidationError):audit.validate_repo(repo,audit.CHALLENGE_ORIGIN,"0"*40)
 def test_safe_archive_extracts_regular_file(self):
  data=io.BytesIO()
  with tarfile.open(fileobj=data,mode="w") as tf:
   item=tarfile.TarInfo("include/a.h");payload=b"ok";item.size=len(payload);tf.addfile(item,io.BytesIO(payload))
  with tempfile.TemporaryDirectory() as td:
   audit.safe_extract_tar(data.getvalue(),pathlib.Path(td));self.assertEqual((pathlib.Path(td)/"include/a.h").read_bytes(),b"ok")
 def test_archive_traversal_and_links_rejected(self):
  for name,link in (("../escape",False),("link",True)):
   data=io.BytesIO()
   with tarfile.open(fileobj=data,mode="w") as tf:
    item=tarfile.TarInfo(name);item.type=tarfile.SYMTYPE if link else tarfile.REGTYPE;item.linkname="outside" if link else "";tf.addfile(item,io.BytesIO(b"") if not link else None)
   with tempfile.TemporaryDirectory() as td:
    with self.assertRaises(audit.ValidationError):audit.safe_extract_tar(data.getvalue(),pathlib.Path(td))
 def test_conditional_h_baseline(self):
  got=audit.conditional_h_agreement([192,193],[193,192],8192)
  expected=sum(1-x/8192-y/8192+2*x*y/8192**2 for x,y in ((192,193),(193,192)))/2
  self.assertEqual(got,expected);self.assertNotEqual(got,.5)
 def test_conditional_h_rejects_bad_vectors(self):
  for a,b in (([],[]),([1],[1,2])):
   with self.assertRaises(audit.ValidationError):audit.conditional_h_agreement(a,b,8192)
 def test_conditional_h_moments_preserve_realized_pairing(self):
  hist={"192":1,"193":1}
  aligned=audit.conditional_h_agreement_from_moments(hist,hist,192*192+193*193,2,8192)
  crossed=audit.conditional_h_agreement_from_moments(hist,hist,2*192*193,2,8192)
  self.assertNotEqual(aligned,crossed)
  self.assertEqual(crossed,audit.conditional_h_agreement([192,193],[193,192],8192))
 def test_nearest_control_deterministic_compact_descriptive(self):
  a=audit.simulate_nearest_null(128,18,18,337);b=audit.simulate_nearest_null(128,18,18,337)
  self.assertEqual(a,b);self.assertIn("descriptive",a["model"]);self.assertNotIn("raw_trial_means",a)
 def test_permutation_deterministic_compact(self):
  a=[f"{x:064x}" for x in (1,3,7)];b=[f"{x:064x}" for x in (15,31,63,127)]
  x=audit.commitment_permutation_control(a,b,337,128);self.assertEqual(x,audit.commitment_permutation_control(a,b,337,128));self.assertIn("inferential",x["model"])
 def test_committed_document_validates(self): audit.validate_document(self.result())
 def test_validator_rejects_pin_pair_digest_canonical_and_collision_mutations(self):
  mutations=(lambda d:d["pins"].update(challenge_commit="0"*40),lambda d:d["pairs"].pop(),
             lambda d:d["chronology"][0]["artifact_sha256"].update(pk="0"*64),
             lambda d:d["chronology"][0]["canonical_tags"].update(verified=d["chronology"][0]["counts"]["base_nonces"],mismatches=0,recomputed=0),
             lambda d:d["source_provenance"]["analyzer_sources"].update({"audit.py":"0"*64}),
             lambda d:d["aligned_character_scan"].update(exact_zero=1))
  for mutate in mutations:
   d=self.result();mutate(d)
   with self.assertRaises(audit.ValidationError):audit.validate_document(d)
 def test_document_has_no_raw_paths_or_secret_markers(self):
  text=json.dumps(self.result());
  for marker in ("raw_distances","secret.ct","pk.bin","/tmp/",str(pathlib.Path.home())):self.assertNotIn(marker,text)
 def test_help_lists_check_output(self):
  r=subprocess.run([sys.executable,str(HERE/"audit.py"),"--help"],text=True,capture_output=True);self.assertEqual(r.returncode,0);self.assertIn("--check-output",r.stdout)

if __name__=="__main__":unittest.main()
