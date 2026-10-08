import copy
import json
import pathlib
import tempfile
import unittest
from adapt import from_analyzer
from migrate import compile_snapshot
from validation import read_json
ROOT = pathlib.Path(__file__).parent
class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT/'examples/snapshot.json').read_text())
        self.mapping = json.loads((ROOT/'examples/mapping.json').read_text())
    def rejects(self):
        with self.assertRaises(ValueError): compile_snapshot(self.data,self.mapping)
    def test_string_disabled(self):
        self.data['rules'][0]['disabled']='false'; self.rejects()
    def test_string_member_complete(self):
        self.data['groups'][0]['members_complete']='true'; self.rejects()
    def test_duplicate_group(self):
        self.data['groups'].append(copy.deepcopy(self.data['groups'][0]));self.rejects()
    def test_duplicate_service(self):
        self.data['services'].append(copy.deepcopy(self.data['services'][0]));self.rejects()
    def test_target_collision(self):
        self.mapping['assets'][1]['new_ips']=self.mapping['assets'][0]['new_ips'];self.rejects()
    def test_mixed_any(self):
        self.data['rules'][0]['source_groups']=['ANY',self.data['groups'][0]['path']];self.rejects()
    def test_string_reference_list(self):
        self.data['rules'][0]['scope']='ANY';self.rejects()
    def test_string_order(self):
        self.data['rules'][0]['effective_order']='1';self.rejects()
    def test_empty_snapshot(self):
        self.data['rules']=[];self.rejects()
    def test_conflicting_mapping(self):
        self.mapping['address_map']={'192.168.10.11/32':'10.0.9.9/32'};self.rejects()
    def test_retained_range_overlaps_migrated(self):
        self.mapping['retain_addresses']=['192.168.10.0/24'];self.rejects()
    def test_cidr_mapping_inconsistent(self):
        self.mapping['address_map']={'192.168.10.0/24':'10.0.9.0/24'};self.rejects()
    def test_ipv6_alias_collision(self):
        self.mapping['assets'][0].update(old_ips=['2001:db8::1'],new_ips=['2001:db8:1::1'])
        self.mapping['assets'][1].update(old_ips=['2001:db8::2'],new_ips=['2001:db8:1:0:0:0:0:1']);self.rejects()
    def test_malformed_ports_fail_closed(self):
        self.data['services'][0]['service_entries'][0]['destination_ports']='3306'
        plan=compile_snapshot(self.data,self.mapping)
        self.assertEqual(plan['status'],'blocked')
        self.assertEqual(plan['security_group_requests'],[])
    def test_canonical_address_mapping(self):
        self.mapping['assets'][0].update(old_ips=['2001:db8::1'],new_ips=['2001:db8:1::1'])
        self.mapping['assets'][1].update(old_ips=['2001:db8::2'],new_ips=['2001:db8:1::2'])
        self.data['groups'][0]['members']=['2001:db8:0:0:0:0:0:1']
        self.data['groups'][1]['members']=['2001:db8::2/128']
        self.data['rules'][0]['ip_protocol']='IPV6'
        self.assertEqual(compile_snapshot(self.data,self.mapping)['status'],'review_required')
    def test_json_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'a.json';p.write_text('{"disabled":false,"disabled":true}')
            with self.assertRaises(ValueError):read_json(p)
    def test_nonfinite_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'a.json';p.write_text('{"order":NaN}')
            with self.assertRaises(ValueError):read_json(p)
    def test_manifest_truthy_string(self):
        d=json.loads((ROOT/'public-sample/Example1.json').read_text())
        m=json.loads((ROOT/'demo/mapping.json').read_text())
        manifest=json.loads((ROOT/'demo/manifest.json').read_text());manifest['export_complete']='false'
        with self.assertRaises(ValueError):from_analyzer(d,m,manifest)
    def test_empty_scope_does_not_inherit(self):
        d=json.loads((ROOT/'public-sample/Example1.json').read_text())
        m=json.loads((ROOT/'demo/mapping.json').read_text())
        manifest=json.loads((ROOT/'demo/manifest.json').read_text())
        d['domains'][0]['resources']['security_policies'][0]['rules'][0]['scope']=[]
        with self.assertRaises(ValueError):from_analyzer(d,m,manifest)
    def test_expansion_is_blocked_before_output(self):
        self.data['groups'][0]['members']=['198.51.100.1','198.51.100.2']
        self.mapping['retain_addresses']=['198.51.100.1','198.51.100.2']
        plan=compile_snapshot(self.data,self.mapping,1)
        self.assertEqual(plan['status'],'blocked');self.assertEqual(plan['security_group_requests'],[])
if __name__=='__main__':unittest.main()
