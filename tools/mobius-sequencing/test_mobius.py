#!/usr/bin/env python3
import importlib.util, pathlib, unittest
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("mobius",HERE/"mobius.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
 def test_twisted_partner_reverses_orientation(self):
  self.assertEqual(m.twisted_partner(0,0,22,0),(21,1))
  self.assertEqual(m.twisted_partner(3,1,22,2),(16,0))
 def test_cylinder_partner_preserves_orientation(self):
  self.assertEqual(m.cylinder_partner(3,1,22,2),(5,1))
 def test_antiperiodic_modes_have_half_integer_frequencies(self):
  self.assertEqual(m.antiperiodic_frequencies(4),[0.5,1.5,2.5,3.5])
 def test_subset_mobius_round_trip(self):
  values=[3,5,7,11,13,17,19,23]
  self.assertEqual(m.subset_zeta(m.subset_mobius(values)),values)
 def test_fractional_linear_handles_projective_infinity(self):
  p=127
  self.assertEqual(m.fractional_linear(5,(1,0,0,1),p),5)
  self.assertIsNone(m.fractional_linear(5,(1,0,1,-5),p))
  self.assertEqual(m.fractional_linear(None,(0,1,1,0),p),0)
 def test_plus_one_permutation_p(self):
  self.assertEqual(m.plus_one_p(4,9),0.5)
 def test_holm_bonferroni(self):
  self.assertEqual(m.holm_bonferroni([0.001,0.02,0.5],0.05),[True,True,False])
 def test_bit_reversal_is_involution(self):
  self.assertEqual(m.bit_reverse(m.bit_reverse(13,8),8),13)

if __name__=="__main__":unittest.main()
