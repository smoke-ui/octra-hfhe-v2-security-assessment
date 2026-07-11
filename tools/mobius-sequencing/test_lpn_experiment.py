#!/usr/bin/env python3
import importlib.util, hashlib, io, json, pathlib, subprocess, sys, tarfile, tempfile, unittest
import numpy as np
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("lpn_experiment",HERE/"lpn_experiment.py")
e=importlib.util.module_from_spec(spec);sys.modules[spec.name]=e;spec.loader.exec_module(e)

class Tests(unittest.TestCase):
 def fixture(self, root):
  for c in range(2):
   for l in range(2):
    p=pathlib.Path(root)/f"ct{c:02d}_l{l}_s0_pvac_prf_r_1.jsonl"
    h={"format":e.FORMAT,"cipher_index":c,"layer_id":l,"slot":0,"dom":"pvac.prf.r.1","n":64,"t":4,"tau_num":1,"tau_den":8,"row_words":1,"seed_ztag":c*2+l,"nonce_lo_hex":"0"*16,"nonce_hi_hex":"1"*16,"public_T_hex":"2"*32}
    rows=[{"i":i,"y":i%2,"a":f"{(i+c+l):016x}"} for i in range(4)]
    p.write_text("\n".join(map(json.dumps,[h,*rows]))+"\n")
 def challenge_repo(self, root, corrupt=False):
  repo=pathlib.Path(root)/"challenge"; repo.mkdir(); samples=repo/"lpn_samples"; samples.mkdir()
  self.fixture(samples); entries=[]
  for p in sorted(samples.iterdir()): entries.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  lpn_samples/{p.name}")
  (repo/"SHA256SUMS").write_text("\n".join(entries)+"\n")
  if corrupt:
   p=next(samples.iterdir()); p.write_bytes(p.read_bytes()+b" ")
  subprocess.run(["git","init","-q",repo],check=True)
  subprocess.run(["git","-C",repo,"config","user.email","test@example.invalid"],check=True)
  subprocess.run(["git","-C",repo,"config","user.name","test"],check=True)
  subprocess.run(["git","-C",repo,"remote","add","origin","https://github.com/octra-labs/hfhe-challenge.git"],check=True)
  subprocess.run(["git","-C",repo,"add","."],check=True); subprocess.run(["git","-C",repo,"commit","-qm","fixture"],check=True)
  commit=subprocess.check_output(["git","-C",repo,"rev-parse","HEAD"],text=True).strip()
  return repo,commit
 def test_challenge_archive_binds_origin_commit_manifest_and_analyzer(self):
  with tempfile.TemporaryDirectory() as d:
   repo,commit=self.challenge_repo(d)
   data,provenance=e.load_challenge_dataset(repo,commit=commit,expected_ciphertexts=2,analyzer=HERE/"lpn_experiment.py")
   self.assertEqual(len(data),4); self.assertEqual(provenance["challenge_commit"],commit)
   self.assertEqual(provenance["challenge_repository"],"octra-labs/hfhe-challenge"); self.assertEqual(provenance["files"],4)
   self.assertRegex(provenance["manifest_sha256"],r"^[0-9a-f]{64}$"); self.assertRegex(provenance["dataset_sha256"],r"^[0-9a-f]{64}$")
   self.assertEqual(provenance["analyzer_sha256"],hashlib.sha256((HERE/"lpn_experiment.py").read_bytes()).hexdigest())
 def test_challenge_archive_rejects_substituted_origin(self):
  with tempfile.TemporaryDirectory() as d:
   repo,commit=self.challenge_repo(d); subprocess.run(["git","-C",repo,"remote","set-url","origin","https://github.com/attacker/hfhe-challenge"],check=True)
   with self.assertRaisesRegex(ValueError,"origin"): e.load_challenge_dataset(repo,commit=commit,expected_ciphertexts=2,analyzer=HERE/"lpn_experiment.py")
 def test_challenge_archive_rejects_file_mutation_against_sha256sums(self):
  with tempfile.TemporaryDirectory() as d:
   repo,commit=self.challenge_repo(d,corrupt=True)
   with self.assertRaisesRegex(ValueError,"checksum"): e.load_challenge_dataset(repo,commit=commit,expected_ciphertexts=2,analyzer=HERE/"lpn_experiment.py")
 def test_safe_archive_rejects_traversal_and_links(self):
  for name,kind in (("../escape",tarfile.REGTYPE),("lpn_samples/link",tarfile.SYMTYPE)):
   stream=io.BytesIO()
   with tarfile.open(fileobj=stream,mode="w") as tf:
    info=tarfile.TarInfo(name); info.type=kind; info.size=0
    if kind==tarfile.SYMTYPE: info.linkname="target"
    tf.addfile(info,io.BytesIO())
   with tempfile.TemporaryDirectory() as d, self.assertRaisesRegex(ValueError,"unsafe archive"):
    e.safe_extract_archive(stream.getvalue(),pathlib.Path(d))
 def test_strict_loader_and_battery_are_deterministic(self):
  with tempfile.TemporaryDirectory() as d:
   self.fixture(d); data=e.load_dataset(pathlib.Path(d),expected_ciphertexts=2)
   self.assertEqual((len(data),sum(len(x.rows) for x in data)),(4,16))
   a=e.run_battery(data,lags=(1,),row_subset=range(4),trials=19,seed=7,provenance={"dataset_sha256":"a"*64})
   b=e.run_battery(data,lags=(1,),row_subset=range(4),trials=19,seed=7,provenance={"dataset_sha256":"a"*64})
   self.assertEqual(a,b); self.assertEqual(a["design"]["seam_scan_family"],16)
   self.assertEqual(a["provenance"]["dataset_sha256"],"a"*64)
   self.assertTrue(a["design"]["exploratory"])
   self.assertTrue(all(0 < x["p_plus_one"] <= 1 for x in a["tests"]))
 def test_loader_fails_closed_on_bad_row_index(self):
  with tempfile.TemporaryDirectory() as d:
   self.fixture(d); p=pathlib.Path(d)/"ct00_l0_s0_pvac_prf_r_1.jsonl"
   lines=p.read_text().splitlines(); row=json.loads(lines[2]); row["i"]=9; lines[2]=json.dumps(row); p.write_text("\n".join(lines)+"\n")
   with self.assertRaisesRegex(ValueError,"row index"): e.load_dataset(pathlib.Path(d),expected_ciphertexts=2)
 def test_holm_adjustment_is_monotone_in_sorted_order(self):
  self.assertEqual(e.holm_adjust([.01,.04,.03]),[.03,.06,.06])
 def test_bit_coordinate_maps_are_the_four_predeclared_transforms(self):
  # bytes 00000001 10000000 -> global, per-byte, and combined reversal
  value=int.from_bytes(bytes([1,128]),"little")
  self.assertEqual(e.bit_transforms(value,16),{
   "identity":value,
   "global_reversal":value,
   "per_byte_reversal":int.from_bytes(bytes([128,1]),"little"),
   "global_and_per_byte_reversal":int.from_bytes(bytes([1,128]),"big"),
  })
 def test_periodic_fft_scan_returns_every_shift(self):
  a=np.array([1.,-1.,-1.,1.]); b=np.roll(a,2)
  got=e.fft_shift_correlations(a,b,antiperiodic=False)
  self.assertEqual(len(got),4)
  self.assertAlmostEqual(float(np.max(got)),1.0)
  self.assertEqual(int(np.argmax(got)),2)
 def test_antiperiodic_fft_scan_matches_direct_signed_wrap(self):
  a=np.array([1.,2.,3.,4.]); b=np.array([-2.,-1.,4.,3.])
  got=e.fft_shift_correlations(a,b,antiperiodic=True)
  direct=[]
  for shift in range(4):
   shifted=np.concatenate((b[shift:],-b[:shift]))
   direct.append(np.dot(a,shifted)/np.sqrt(np.dot(a,a)*np.dot(b,b)))
  np.testing.assert_allclose(got,direct,atol=1e-12)
 def test_battery_uses_all_rows_and_declares_full_seam_family(self):
  with tempfile.TemporaryDirectory() as d:
   self.fixture(d); data=e.load_dataset(pathlib.Path(d),expected_ciphertexts=2)
   report=e.run_battery(data,lags=(1,),row_subset=range(4),trials=3,seed=7)
   self.assertEqual(report["design"]["sequence_length"],16)
   self.assertEqual(report["design"]["seam_scan_family"],16)
   self.assertEqual(report["design"]["bit_transforms"],list(e.BIT_TRANSFORMS))
   self.assertEqual([x["name"] for x in report["tests"]][-2:],
                    ["row_map_minimum_distance","row_map_complement_cancellation"])
 def test_permutation_control_preserves_full_double_cover(self):
  grid=np.arange(2*3*4).reshape(3,2,4)
  got=e.permuted_mobius(grid,[2,0,1],[0,1,0])
  expected=np.concatenate(([grid[2,0],grid[0,1],grid[1,0]],
                           [grid[1,1],grid[0,0],grid[2,1]])).reshape(-1)
  np.testing.assert_array_equal(got,expected)
 def test_json_is_compact_and_sanitized(self):
  out=e.compact_json({"b":1,"a":[2]})
  self.assertEqual(out,'{"a":[2],"b":1}')
  self.assertNotIn("/",out)

if __name__=="__main__":unittest.main()
