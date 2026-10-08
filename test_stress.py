import unittest
from stress_trial import trial
class StressTests(unittest.TestCase):
    def test_seeded_differential_cases(self):
        report=trial()
        self.assertEqual(report['generated_configurations'],40)
        self.assertEqual(report['connection_checks'],30400)
        self.assertEqual(report['mismatches'],0)
if __name__=='__main__':unittest.main()
