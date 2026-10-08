import copy,importlib.util,json,pathlib,unittest
from bounded import compile_bounded
from migrate import compile_snapshot
ROOT=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('batch',ROOT/'complex-samples/run.py');batch=importlib.util.module_from_spec(spec);spec.loader.exec_module(batch)
class BatchFixTests(unittest.TestCase):
    def setUp(self):
        self.d=json.loads((ROOT/'examples/snapshot.json').read_text());self.m=json.loads((ROOT/'examples/mapping.json').read_text())
        self.d['rules'][0]['category']='Application'
    def test_adjacent_ports_merge_without_losing_evidence(self):
        first=self.d['rules'][0];first.update(services=[],service_entries=[{'resource_type':'L4PortSetServiceEntry','l4_protocol':'TCP','destination_ports':['80']}],path='/r/80')
        second=copy.deepcopy(first);second.update(effective_order=2,path='/r/81');second['service_entries'][0]['destination_ports']=['81']
        self.d['rules'].append(second)
        plan=compile_bounded(self.d,self.m,limit=2)
        self.assertEqual(plan['status'],'bounded_review_required')
        self.assertEqual(plan['connections'][0]['port'],'80-81')
        self.assertEqual(len(plan['connections'][0]['source_rule_segments']),2)
        _,differences=batch.evaluate(self.d,plan,self.m,minimum_port=1)
        self.assertFalse(differences)
    def test_gap_is_not_merged(self):
        r=self.d['rules'][0];r.update(services=[],service_entries=[{'resource_type':'L4PortSetServiceEntry','l4_protocol':'TCP','destination_ports':['80','82']}])
        self.assertEqual([c['port'] for c in compile_bounded(self.d,self.m)['connections']],['80','82'])
    def test_verifier_ipv6_and_nested(self):
        d=json.loads((ROOT/'advanced-samples/ipv6-nested-snapshot.json').read_text())
        m=json.loads((ROOT/'advanced-samples/ipv6-mapping.json').read_text())
        plan=compile_bounded(d,m);checks,failures=batch.evaluate(d,plan,m,1)
        self.assertGreater(checks,0);self.assertEqual(failures,[])
    def test_verifier_family_filter(self):
        d=json.loads((ROOT/'advanced-samples/ipv6-nested-snapshot.json').read_text());m=json.loads((ROOT/'advanced-samples/ipv6-mapping.json').read_text())
        d['rules'][0]['ip_protocol']='IPV4'
        _,diff=batch.evaluate(d,compile_bounded(d,m),m,1)
        self.assertEqual(diff,[])
    def test_verifier_range(self):
        self.d['groups'][0]['members']=['192.168.10.10-192.168.10.12']
        _,diff=batch.evaluate(self.d,compile_bounded(self.d,self.m),self.m,1)
        self.assertEqual(diff,[])
    def test_ordinary_failure_does_not_prevent_bounded(self):
        self.d['groups'][0]['members']=['192.168.10.10-192.168.10.12']
        self.assertEqual(batch.convert_mode(compile_snapshot,self.d,self.m)['status'],'blocked')
        self.assertEqual(batch.convert_mode(compile_bounded,self.d,self.m)['status'],'bounded_review_required')
    def test_corrupt_candidate_is_detected(self):
        plan=compile_bounded(self.d,self.m)
        plan['security_group_requests'][0]['SecurityGroupPolicySet']['Egress'][0]['Action']='DROP'
        _,diff=batch.evaluate(self.d,plan,self.m,1)
        self.assertTrue(diff)
    def test_ipv4_asset_never_gets_ipv6_peer_rules(self):
        self.d['rules'][0].update(source_groups=['ANY'],destination_groups=['ANY'],services=['ANY'],ip_protocol='IPV4_IPV6')
        plan=compile_snapshot(self.d,self.m)
        self.assertEqual(plan['status'],'review_required')
        self.assertTrue(all('Ipv6CidrBlock' not in p for r in plan['security_group_requests'] for es in r['SecurityGroupPolicySet'].values() for p in es))
    def test_twenty_inputs_all_modes_accounted_for(self):
        reports=batch.run(write_report=False,quiet=True)
        self.assertEqual(len(reports),20)
        for report in reports:
            self.assertIn('status',report);self.assertIn('bounded_status',report)
            self.assertNotEqual(report.get('verification_status'),'error')
            self.assertNotEqual(report.get('bounded_verification_status'),'error')
if __name__=='__main__':unittest.main()
