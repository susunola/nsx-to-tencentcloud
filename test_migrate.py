import copy, json, pathlib, unittest
from migrate import compile_snapshot
ROOT = pathlib.Path(__file__).parent
class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.d = json.loads((ROOT/'examples/snapshot.json').read_text())
        self.m = json.loads((ROOT/'examples/mapping.json').read_text())
    def test_address_change_and_direction(self):
        r = compile_snapshot(self.d, self.m)
        app, db = r['security_group_requests']
        self.assertEqual(app['SecurityGroupPolicySet']['Egress'][0]['CidrBlock'], '10.0.2.21/32')
        self.assertEqual(db['SecurityGroupPolicySet']['Ingress'][0]['CidrBlock'], '10.0.1.11/32')
        self.assertFalse(app['SecurityGroupPolicySet']['Ingress'])
    def test_scope_is_preserved(self):
        self.d['rules'][0]['scope'] = ['/infra/domains/default/groups/db']
        r = compile_snapshot(self.d, self.m)
        self.assertFalse(r['security_group_requests'][0]['SecurityGroupPolicySet']['Egress'])
        self.assertEqual(len(r['security_group_requests'][1]['SecurityGroupPolicySet']['Ingress']), 1)
    def test_unsupported_rule_blocks_entire_plan(self):
        bad = copy.deepcopy(self.d['rules'][0]); bad.update(id='bad',effective_order=2,sources_excluded=True)
        self.d['rules'].append(bad)
        r = compile_snapshot(self.d, self.m)
        self.assertEqual(r['status'], 'blocked'); self.assertFalse(r['security_group_requests'])
    def test_missing_mapping_blocks(self):
        self.d['groups'][0]['members'] = ['192.168.10.99']
        self.assertEqual(compile_snapshot(self.d, self.m)['status'], 'blocked')
    def test_dynamic_group_incomplete_blocks(self):
        self.d['groups'][0]['members_complete'] = False
        self.assertEqual(compile_snapshot(self.d, self.m)['status'], 'blocked')
    def test_drop_order(self):
        deny = copy.deepcopy(self.d['rules'][0]); deny.update(id='deny',effective_order=0,action='DROP')
        self.d['rules'].append(deny)
        es = compile_snapshot(self.d,self.m)['security_group_requests'][1]['SecurityGroupPolicySet']['Ingress']
        self.assertEqual([p['Action'] for p in es], ['DROP','ACCEPT'])
    def test_quota_blocks(self):
        self.assertEqual(compile_snapshot(self.d,self.m,0)['status'], 'blocked')
    def test_source_port_blocks(self):
        self.d['services'][0]['service_entries'][0]['source_ports'] = ['1024-65535']
        self.assertEqual(compile_snapshot(self.d,self.m)['status'], 'blocked')
    def test_shared_group_blocks(self):
        self.m['assets'][1]['security_group_id'] = self.m['assets'][0]['security_group_id']
        with self.assertRaises(ValueError): compile_snapshot(self.d,self.m)
if __name__ == '__main__': unittest.main()
