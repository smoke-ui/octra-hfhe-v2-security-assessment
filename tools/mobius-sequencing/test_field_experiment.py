#!/usr/bin/env python3
import importlib.util, io, json, pathlib, tarfile, tempfile, unittest
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("field_experiment",HERE/"field_experiment.py")
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

class FieldExperimentTests(unittest.TestCase):
 def extractor_stream(self, mutate=None):
  rows=[{"type":"meta","schema":"pvac-character-spectrum-v2","order":337,"field":"2^127-1","c0_convention":"added_to_every_character_sum","ciphers":22}]
  spectrum=[format(i,"x") for i in range(f.ORDER)]
  rows += [{"type":"layer","cipher":c,"layer":layer,"slot":0,"rule":"base","spectrum":spectrum}
           for c in range(22) for layer in range(2)]
  rows.append({"type":"end","records":44})
  if mutate: mutate(rows)
  return "\n".join(map(json.dumps,rows))

 def test_small_maps_are_exactly_normalized_224(self):
  maps=f.small_pgl2_maps()
  self.assertEqual(len(maps),224); self.assertEqual(len(set(maps)),224)
  for m in maps:
   self.assertEqual(f.gcd4(m),1); self.assertGreater(next(x for x in m if x),0)
   self.assertNotEqual((m[0]*m[3]-m[1]*m[2])%f.ORDER,0)

 def test_projective_map_is_a_permutation_and_handles_pole(self):
  m=(1,0,1,-5); xs=list(range(f.ORDER))+[None]
  ys=[f.fractional_linear(x,m) for x in xs]
  self.assertEqual(len(set(ys)),f.ORDER+1); self.assertIsNone(ys[5]); self.assertEqual(ys[-1],1)

 def test_character_spectrum_and_twists_detect_reversal(self):
  a=[pow(7,k,f.FIELD) for k in range(f.ORDER)]
  b=[a[-k%f.ORDER] for k in range(f.ORDER)]
  r=f.compare_spectra(a,b)
  self.assertTrue(r["k_negation"]); self.assertEqual(r["twist_agreements"],[f.ORDER-1])

 def test_pgl2_maps_act_on_field_values_not_coordinate_indices(self):
  a=[3]*f.ORDER; b=[5]*f.ORDER
  hit=f.compare_value_map(a,b,(1,2,0,1))
  self.assertEqual(hit,{"agreements":f.ORDER,"zeros":0,"poles":0,"collisions":f.ORDER-1})
  pole=f.compare_value_map([0]*f.ORDER,b,(0,1,1,0))
  self.assertEqual(pole["poles"],f.ORDER)

 def test_extractor_protocol_contains_character_sums(self):
  text=self.extractor_stream()
  parsed=f.parse_extractor(text)
  self.assertEqual(parsed["layers"][0]["spectrum"],list(range(f.ORDER)))
  bad=text.replace('"spectrum"','"coeff"',1)
  with self.assertRaises(ValueError): f.parse_extractor(bad)

 def test_repository_identity_is_exact_not_substring(self):
  good=("git@github.com:octra-labs/hfhe-challenge.git","https://github.com/octra-labs/hfhe-challenge.git")
  for url in good:self.assertEqual(f.canonical_repo_identity(url),"octra-labs/hfhe-challenge")
  with self.assertRaises(ValueError):f.canonical_repo_identity("git@evil.example:github.com:octra-labs/hfhe-challenge.git")

 def test_zeros_poles_collisions_and_core_maps(self):
  seq=list(range(f.ORDER))+[None]
  stats=f.map_diagnostics(seq,(0,1,1,0))
  self.assertEqual(stats["poles"],1); self.assertEqual(stats["zeros"],1); self.assertEqual(stats["collisions"],0)
  self.assertEqual(set(f.CORE_MAPS),{"identity","negation","inverse","cayley"})

 def test_cross_ratios_are_mobius_invariant(self):
  xs=[1,2,4,8,16,32]
  m=(2,1,1,1); ys=[f.fractional_linear(x,m,f.FIELD) for x in xs]
  self.assertEqual(f.consecutive_cross_ratios(xs),f.consecutive_cross_ratios(ys))

 def test_quotient_labels_and_seam_ratio(self):
  layers=[[3,6,12],[15,30,60]]
  self.assertEqual(f.quotient_x337_labels(layers),[f.pow337(5)]*3)
  self.assertEqual(f.seam_ratios(layers),[5,5,5])

 def test_toy_positive_and_coordinate_controls(self):
  controls=f.run_controls()
  self.assertTrue(controls["toy_reversal_detected"])
  self.assertEqual(controls["coordinate_twists"],f.ORDER-1)
  self.assertGreaterEqual(controls["max_twist_family"],controls["identity_family"])
  self.assertIn("max_map_family",controls)

 def test_protocol_rejects_malformed_or_incomplete_records(self):
  with self.assertRaises(ValueError): f.parse_extractor('not json\n')
  with self.assertRaises(ValueError): f.parse_extractor(json.dumps({"type":"meta","order":337})+'\n')

 def test_protocol_requires_exact_schema_ordering_and_complete_grid(self):
  self.assertEqual(len(f.parse_extractor(self.extractor_stream())["layers"]),44)
  mutations=(lambda r:r[0].update(extra=1),lambda r:r[1].update(cipher=True),
   lambda r:r[1].update(slot=1),lambda r:r[1].update(rule="prod"),
   lambda r:r.insert(1,dict(r[1])),lambda r:r.insert(0,r.pop(1)),
   lambda r:r.append({"type":"end","records":44}),lambda r:r.append(r.pop(-2)),lambda r:r.pop(1))
  for mutate in mutations:
   with self.subTest(mutate=mutate):
    with self.assertRaises(ValueError): f.parse_extractor(self.extractor_stream(mutate))

 def test_safe_tar_rejects_unsafe_members(self):
  cases=(("../escape",tarfile.REGTYPE,""),("/absolute",tarfile.REGTYPE,""),("link",tarfile.SYMTYPE,"target"),("device",tarfile.CHRTYPE,""))
  for name,kind,link in cases:
   data=io.BytesIO()
   with tarfile.open(fileobj=data,mode="w") as archive:
    info=tarfile.TarInfo(name);info.type=kind;info.linkname=link;archive.addfile(info)
   data.seek(0)
   with tempfile.TemporaryDirectory() as td:
    with self.subTest(name=name):
     with self.assertRaises(ValueError):f.safe_extract_tar(data,pathlib.Path(td))

 def test_compact_report_has_no_paths_or_raw_spectra(self):
  report=f.analyze_records(f.toy_records())
  blob=json.dumps(report,sort_keys=True,separators=(",",":"))
  self.assertNotIn(str(HERE),blob); self.assertNotIn('spectra',report)
  self.assertEqual(report["schema"],"field-mobius-v2")

if __name__=='__main__': unittest.main()
