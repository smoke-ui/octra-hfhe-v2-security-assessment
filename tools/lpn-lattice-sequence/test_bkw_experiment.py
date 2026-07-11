#!/usr/bin/env python3
import importlib.util, pathlib, sys, unittest
HERE=pathlib.Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("bkw_experiment",HERE/"bkw_experiment.py")
b=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=b;SPEC.loader.exec_module(b)

class Tests(unittest.TestCase):
 def test_noise_metrics_are_unambiguous(self):
  self.assertEqual(b.noise_metrics(1,8,3),{
   "correlation":{"numerator":27,"denominator":64},
   "error_probability":{"numerator":37,"denominator":128},
   "correctness_probability":{"numerator":91,"denominator":128},
   "centered_bias":{"numerator":27,"denominator":128}})

 def test_binomial_lower_tail_is_exact_at_boundaries(self):
  self.assertEqual(b.binomial_half_lower_tail(4,1),b.Fraction(5,16))
  self.assertEqual(b.binomial_half_lower_tail(4,-1),b.Fraction(0,1))
  self.assertEqual(b.binomial_half_lower_tail(4,4),b.Fraction(1,1))

 def test_significance_uses_conditioned_dimension_and_exact_small_tail(self):
  interesting=b.result_significance(effective_random_dimension=3,weight=1,candidate_evaluations=1,
                                    actionable=False,alpha=b.Fraction(1,2))
  self.assertEqual(interesting["random_row_lower_tail"],{"numerator":1,"denominator":2})
  self.assertEqual(interesting["effective_random_dimension"],3)
  self.assertIn("conditioned",interesting["null_model"])

 def test_significance_uses_union_bound_and_classifies_defensibly(self):
  interesting=b.result_significance(effective_random_dimension=4,weight=0,candidate_evaluations=1,
                                    actionable=False,alpha=b.Fraction(1,10))
  self.assertEqual(interesting["random_row_lower_tail"],{"numerator":1,"denominator":16})
  self.assertEqual(interesting["family_wise_error_rate"],{"numerator":1,"denominator":16})
  self.assertEqual(interesting["classification"],"statistically_interesting_only")
  self.assertNotIn("independent",interesting["null_model"])
  bounded=b.result_significance(effective_random_dimension=4,weight=0,candidate_evaluations=2,
                                actionable=False,alpha=b.Fraction(1,10))
  self.assertEqual(bounded["classification"],"bounded_null")
  actionable=b.result_significance(effective_random_dimension=4,weight=0,candidate_evaluations=1,
                                   actionable=True,alpha=b.Fraction(1,10))
  self.assertEqual(actionable["family_wise_error_rate"],{"numerator":1,"denominator":16})
  self.assertEqual(actionable["classification"],"computationally_actionable")
  nonsignificant=b.result_significance(effective_random_dimension=4,weight=4,candidate_evaluations=16,
                                      actionable=True,alpha=b.Fraction(1,400))
  self.assertEqual(nonsignificant["classification"],"bounded_null")

 def test_estimator_is_not_claimed_as_execution(self):
  rows=b.parameter_estimator(n=64,samples=32,tau_num=1,tau_den=8,blocks=(4,),stages=(2,))
  self.assertEqual(rows[0]["kind"],"analytic_estimate")
  self.assertNotIn("executed",rows[0])

 def test_bucket_run_reports_coverage_and_computed_actionability(self):
  rows=[b.Equation(a,0,(i,)) for i,a in enumerate((1,5,2,10))]
  report=b.exact_bucket_run(rows,n=4,blocks=((0,2),),tau_num=1,tau_den=8,
                            criterion={"max_terminal_dimension":2,"max_residual_direct_budget":4,
                                       "max_terminal_mitm_budget":2})
  self.assertEqual(report["scope"]["rows_examined"],4)
  self.assertEqual(report["outcome"]["minimum_residual_weight"],1)
  self.assertTrue(report["outcome"]["actionability"]["actionable"])
  self.assertNotIn("work",report["outcome"]["actionability"]["checks"])
  self.assertEqual(report["outcome"]["work"]["unit"],"row_visits")

 def test_lsh_search_covers_all_rows_and_reports_realized_comparisons(self):
  rows=[b.Equation(x,0,(i,)) for i,x in enumerate((0xf0,0xf1,0x30,0x32,0xaa))]
  r=b.lsh_nearest(rows,n=8,projection_bits=2,tables=2,bucket_cap=8,top_k=3,seed=7)
  self.assertEqual(r["scope"]["rows_examined"],5)
  self.assertEqual(r["scope"]["tables"],2)
  self.assertGreater(r["scope"]["comparisons_examined"],0)
  self.assertEqual(r["scope"]["candidate_evaluations_upper_bound"],r["scope"]["comparisons_examined"])
  self.assertTrue(r["scope"]["exact_unique_count_not_retained"])
  self.assertTrue(r["scope"]["comparisons_include_repeats"])
  self.assertEqual(r["outcome"]["minimum_residual_weight"],1)

 def test_disjoint_shard_mitm_reports_triple_and_quad_counts(self):
  rows=[b.Equation(x,0,(i,)) for i,x in enumerate((0xf0,0x0f,0x33,0xcc,0xf1,0x0e,0x32,0xcd))]
  r=b.disjoint_shard_mitm(rows,n=8,shard_size=2,projection_bits=2)
  self.assertEqual(r["scope"]["shards"],4)
  self.assertEqual(r["scope"]["rows_examined"],8)
  self.assertEqual(set(r["outcomes"]),{"triple","quadruple"})
  self.assertGreater(r["outcomes"]["triple"]["combinations_examined"],0)
  self.assertEqual(r["outcomes"]["quadruple"]["combination_size"],4)
  self.assertEqual(r["scope"]["triple_right_singletons"],2)
  self.assertEqual(r["scope"]["quad_pair_sums_per_side"],4)

 def test_matched_control_uses_identical_pipeline(self):
  rows=[b.Equation(x,i&1,(i,)) for i,x in enumerate(range(16))]
  r=b.experiment(rows,n=8,tau_num=1,tau_den=8,seed=9,blocks=((0,2),),lsh_projection_bits=2,lsh_tables=2,lsh_bucket_cap=8,lsh_top_k=3,mitm_shard_size=2,mitm_projection_bits=2)
  self.assertEqual(r["observed"]["pipeline"],r["matched_random_control"]["pipeline"])
  for side in ("observed","matched_random_control"):
   families=r[side]["families"]
   bucket=families[0]
   self.assertEqual(bucket["outcome"]["significance"]["candidate_evaluations"],
                    bucket["outcome"]["equations_retained"])
   self.assertEqual(bucket["outcome"]["significance"]["effective_random_dimension"],6)
   self.assertNotEqual(bucket["scope"]["row_visits"],bucket["outcome"]["equations_retained"])
   lsh=families[1]
   self.assertEqual(lsh["outcome"]["significance"]["candidate_evaluations"],
                    lsh["scope"]["comparisons_examined"])
   self.assertEqual(lsh["outcome"]["significance"]["effective_random_dimension"],6)
   self.assertIn("actionability",lsh["outcome"])
   for name in ("triple","quadruple"):
    outcome=families[2]["outcomes"][name]
    self.assertEqual(outcome["significance"]["candidate_evaluations"],outcome["combinations_examined"])
    self.assertEqual(outcome["significance"]["effective_random_dimension"],6)
    self.assertIn(outcome["significance"]["classification"],
                  {"bounded_null","statistically_interesting_only","computationally_actionable"})
    self.assertIn("actionability",outcome)
  self.assertEqual(r,b.experiment(rows,n=8,tau_num=1,tau_den=8,seed=9,blocks=((0,2),),lsh_projection_bits=2,lsh_tables=2,lsh_bucket_cap=8,lsh_top_k=3,mitm_shard_size=2,mitm_projection_bits=2))
  self.assertEqual(r["design"]["multiple_testing"]["executed_families"],4)
  self.assertEqual(r["design"]["multiple_testing"]["per_family_alpha"],{"numerator":1,"denominator":400})
  for side in ("observed","matched_random_control"):
   self.assertIn("global_union_bound",r[side])
   self.assertLessEqual(r[side]["global_union_bound"]["numerator"],r[side]["global_union_bound"]["denominator"])

 def test_compact_output_rejects_paths_raw_rows_and_ids(self):
  self.assertEqual(b.compact_json({"actionable":False}),'{"actionable":false}')
  for bad in ({"path":"/tmp/x"},{"raw_rows":[1]},{"source_ids":[1]}):
   with self.assertRaisesRegex(ValueError,"unsafe output"): b.compact_json(bad)

if __name__=="__main__": unittest.main()
