import copy,json,pathlib,unittest
from bounded import compile_bounded
ROOT=pathlib.Path(__file__).parent
class BoundedTests(unittest.TestCase):
    def setUp(self):
        self.d=json.loads((ROOT/'examples/snapshot.json').read_text())
        self.m=json.loads((ROOT/'examples/mapping.json').read_text())
        self.d['rules'][0]['category']='Application'
    def test_basic_trace(self):
        r=compile_bounded(self.d,self.m)
        self.assertEqual(r['status'],'bounded_review_required')
        self.assertEqual(len(r['connections']),1)
        self.assertEqual(r['connections'][0]['port'],'3306')
    def test_jump_skips_environment_deny(self):
        allow=copy.deepcopy(self.d['rules'][0]);allow['effective_order']=2
        jump=copy.deepcopy(allow);jump.update(action='JUMP_TO_APPLICATION',category='Environment',effective_order=0,id='jump')
        deny=copy.deepcopy(jump);deny.update(action='DROP',effective_order=1,id='deny')
        self.d['rules']=[jump,deny,allow]
        self.assertEqual(len(compile_bounded(self.d,self.m)['connections']),1)
        self.d['rules']=[deny,allow]
        self.assertEqual(len(compile_bounded(self.d,self.m)['connections']),0)
    def test_invalid_jump_category(self):
        self.d['rules'][0]['action']='JUMP_TO_APPLICATION'
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'blocked')
    def test_negation_matches_complement_within_domain(self):
        self.d['rules'][0]['destination_groups']=[self.d['groups'][0]['path']]
        self.d['rules'][0]['destinations_excluded']=True
        r=compile_bounded(self.d,self.m)
        self.assertEqual(len(r['connections']),1)
    def test_incomplete_negated_group_blocks(self):
        self.d['rules'][0]['destinations_excluded']=True
        self.d['groups'][1]['members_complete']=False
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'blocked')
    def test_budget_blocks(self):
        self.assertEqual(compile_bounded(self.d,self.m,1)['status'],'blocked')
    def test_no_external_any(self):
        self.d['rules'][0].update(source_groups=['ANY'],destination_groups=['ANY'],services=['ANY'])
        r=compile_bounded(self.d,self.m)
        self.assertEqual(r['status'],'bounded_review_required')
        for req in r['security_group_requests']:
            for es in req['SecurityGroupPolicySet'].values():
                self.assertTrue(all(p['CidrBlock'].endswith('/32') for p in es if p['Action']=='ACCEPT'))
    def test_multinic_blocks(self):
        self.m['assets'][0]['old_ips'].append('192.168.10.12');self.m['assets'][0]['new_ips'].append('10.0.1.12')
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'blocked')
if __name__=='__main__':unittest.main()
