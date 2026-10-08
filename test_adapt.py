import copy, json, pathlib, tempfile, unittest
from adapt import from_analyzer, from_aws
from migrate import compile_snapshot
ROOT = pathlib.Path(__file__).parent
class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((ROOT/'public-sample/Example1.json').read_text())
        self.mapping=json.loads((ROOT/'demo/mapping.json').read_text())
        self.manifest=json.loads((ROOT/'demo/manifest.json').read_text())
    def test_public_sample(self):
        normalized=from_analyzer(self.data,self.mapping,self.manifest)
        plan=compile_snapshot(normalized,self.mapping)
        self.assertEqual(plan['status'],'review_required')
        a,b=plan['security_group_requests']
        self.assertEqual(a['SecurityGroupPolicySet']['Egress'][0]['Port'],'445')
        self.assertEqual(b['SecurityGroupPolicySet']['Ingress'][0]['CidrBlock'],'10.0.1.11/32')
        self.assertEqual(b['SecurityGroupPolicySet']['Ingress'][1]['Action'],'DROP')
    def test_manifest_required(self):
        self.manifest['export_complete']=False
        with self.assertRaises(ValueError):from_analyzer(self.data,self.mapping,self.manifest)
    def test_missing_vm_mapping(self):
        self.mapping['assets'].pop()
        with self.assertRaises(ValueError):from_analyzer(self.data,self.mapping,self.manifest)
    def test_no_guessing_of_order(self):
        self.manifest['rule_arrays_in_effective_order']=False
        with self.assertRaises(ValueError):from_analyzer(self.data,self.mapping,self.manifest)
    def test_no_guessing_stateful(self):
        self.manifest['rule_defaults']={}
        plan=compile_snapshot(from_analyzer(self.data,self.mapping,self.manifest),self.mapping)
        self.assertEqual(plan['status'],'blocked')
    def aws_fixture(self, root):
        res=self.data['domains'][0]['resources']; p=copy.deepcopy(res['security_policies'][0])
        rules=p.pop('rules');p['id']='app-x'
        for i,r in enumerate(rules):r['sequence_number']=i+1
        for name,value in [('dfw.json',[p]),('dfw_details.json',{'app-x':{'results':rules}}),('cgw-groups.json',res['groups']),('services.json',self.data['services'])]:
            (root/name).write_text(json.dumps(value))
    def test_aws_layout_matches_public_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);self.aws_fixture(root)
            aws=compile_snapshot(from_aws(root,self.mapping,self.manifest),self.mapping)
            direct=compile_snapshot(from_analyzer(self.data,self.mapping,self.manifest),self.mapping)
            self.assertEqual(aws['security_group_requests'],direct['security_group_requests'])
    def test_aws_cursor_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);self.aws_fixture(root)
            p=root/'dfw_details.json';d=json.loads(p.read_text());d['app-x']['cursor']='next';p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):from_aws(root,self.mapping,self.manifest)
    def test_aws_members_require_explicit_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);self.aws_fixture(root)
            self.manifest['allow_vm_members_from_mapping']=False
            plan=compile_snapshot(from_aws(root,self.mapping,self.manifest),self.mapping)
            self.assertEqual(plan['status'],'blocked')
if __name__=='__main__':unittest.main()
