import importlib.util
import pathlib
import unittest
ROOT=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('complex_trial',ROOT/'complex-samples/run.py')
trial=importlib.util.module_from_spec(spec);spec.loader.exec_module(trial)
class ComplexFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reports={r['fixture']:r for r in trial.run(write_report=False,quiet=True)}
    def test_supported_samples_match_sampled_connections(self):
        for name in ['Example1aRedundantRuleInOut.json','ExampleGroup4.json']:
            with self.subTest(fixture=name):
                r=self.reports[name]
                self.assertEqual(r['status'],'review_required')
                self.assertGreater(r['connection_cases'],0)
                self.assertEqual(r['mismatches'],[])
    def test_bounded_advanced_samples(self):
        for name in ['Example2.json','ExampleHogwarts.json','ExampleExprAndCondsExclude.json','ExampleExprOrCondsExclude.json']:
            with self.subTest(fixture=name):
                r=self.reports[name]
                self.assertEqual(r['bounded_status'],'bounded_review_required')
                self.assertGreater(r['bounded_connection_cases'],0)
                self.assertEqual(r['bounded_mismatches'],[])
    def test_jump_is_blocked(self):
        for name in ['Example2.json','ExampleHogwarts.json']:
            with self.subTest(fixture=name):
                r=self.reports[name];self.assertEqual(r['status'],'blocked')
                self.assertTrue(any('ALLOW/DROP' in issue['reason'] for issue in r['issues']))
    def test_negation_is_blocked(self):
        for name in ['ExampleExprAndCondsExclude.json','ExampleExprOrCondsExclude.json','ExampleAppWithGroups.json']:
            with self.subTest(fixture=name):
                r=self.reports[name];self.assertEqual(r['status'],'blocked')
                self.assertTrue(any('Negated' in issue['reason'] for issue in r['issues']))
    def test_unresolved_members_block(self):
        r=self.reports['ExampleExprSingleScope.json']
        self.assertEqual(r['status'],'blocked')
        self.assertTrue(any('complete resolved' in issue['reason'] for issue in r['issues']))
if __name__=='__main__':unittest.main()
