import copy,json,pathlib,unittest
from bounded import compile_bounded
from migrate import compile_snapshot
from service_resolver import ServiceResolver
from addresses import networks
ROOT=pathlib.Path(__file__).parent
class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.d=json.loads((ROOT/'examples/snapshot.json').read_text())
        self.m=json.loads((ROOT/'examples/mapping.json').read_text())
        self.d['rules'][0]['category']='Application'
    def wrap_service(self):
        self.d['services'].append({'path':'/infra/services/wrapper','service_entries':[{'resource_type':'NestedServiceServiceEntry','nested_service_path':'/infra/services/mysql'}]})
        self.d['rules'][0]['services']=['/infra/services/wrapper']
    def test_nested_service_ordinary(self):
        self.wrap_service()
        r=compile_snapshot(self.d,self.m)
        self.assertEqual(r['status'],'review_required')
        self.assertEqual(r['security_group_requests'][0]['SecurityGroupPolicySet']['Egress'][0]['Port'],'3306')
    def test_nested_service_bounded(self):
        self.wrap_service();r=compile_bounded(self.d,self.m)
        self.assertEqual(r['connections'][0]['port'],'3306')
    def test_nested_entry_path(self):
        self.d['services'][0]['service_entries'][0]['path']='/infra/services/mysql/service-entries/one'
        self.wrap_service()
        self.d['services'][1]['service_entries'][0]['nested_service_path']='/infra/services/mysql/service-entries/one'
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'bounded_review_required')
    def test_cycle_blocks_both_compilers(self):
        self.wrap_service();self.d['services'][1]['service_entries'][0]['nested_service_path']='/infra/services/wrapper'
        for compiler in [compile_snapshot,compile_bounded]:
            with self.subTest(compiler=compiler.__name__):
                r=compiler(self.d,self.m);self.assertEqual(r['status'],'blocked');self.assertEqual(r['security_group_requests'],[])
    def test_missing_nested_reference(self):
        self.wrap_service();self.d['services'][1]['service_entries'][0]['nested_service_path']='/missing'
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'blocked')
    def test_depth_limit(self):
        services={f'/s/{i}':{'service_entries':[{'resource_type':'NestedServiceServiceEntry','nested_service_path':f'/s/{i+1}'}]} for i in range(20)}
        with self.assertRaisesRegex(ValueError,'depth'):ServiceResolver(services).expand({'services':['/s/0']})
    def test_fanout_limit(self):
        entry={'resource_type':'L4PortSetServiceEntry','l4_protocol':'TCP','destination_ports':['80']}
        with self.assertRaisesRegex(ValueError,'entry limit'):ServiceResolver({'/s':{'service_entries':[entry]*3}},max_entries=2).expand({'services':['/s']})
    def test_unknown_deleted_entry_blocks(self):
        self.d['services'][0]['service_entries'][0]['marked_for_delete']='false'
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'blocked')
    def ipv6(self):
        for i,a in enumerate(self.m['assets']):
            a.update(old_ips=[f'2001:db8::{i+1}'],new_ips=[f'2001:db8:1::{i+1}'])
            self.d['groups'][i]['members']=[a['old_ips'][0]]
        self.d['rules'][0]['ip_protocol']='IPV6'
    def test_ipv6_bounded_peers(self):
        self.ipv6();r=compile_bounded(self.d,self.m)
        self.assertEqual(r['status'],'bounded_review_required')
        es=r['security_group_requests'][0]['SecurityGroupPolicySet']['Egress']
        self.assertEqual(es[0]['Ipv6CidrBlock'],'2001:db8:1::2/128')
        self.assertEqual(es[-1]['Ipv6CidrBlock'],'::/0')
    def test_ipv4_rule_does_not_leak_to_ipv6(self):
        self.ipv6();self.d['rules'][0]['ip_protocol']='IPV4'
        self.assertFalse(compile_bounded(self.d,self.m)['connections'])
    def test_ipv6_negation_is_family_limited(self):
        self.ipv6();r=self.d['rules'][0]
        r.update(destination_groups=[self.d['groups'][0]['path']],destinations_excluded=True)
        self.assertEqual(len(compile_bounded(self.d,self.m)['connections']),1)
    def test_mixed_families_no_cross_family_connection(self):
        self.m['assets'][1].update(old_ips=['2001:db8::2'],new_ips=['2001:db8:1::2'])
        self.d['groups'][1]['members']=['2001:db8::2']
        self.d['rules'][0]['ip_protocol']='IPV4_IPV6'
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'blocked')
    def test_range_membership(self):
        self.d['groups'][0]['members']=['192.168.10.10-192.168.10.12']
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'bounded_review_required')
    def test_reverse_range(self):
        with self.assertRaises(ValueError):networks('192.0.2.4-192.0.2.1',True)
    def test_strict_hostbits(self):
        with self.assertRaises(ValueError):networks('192.0.2.1/24',True)
    def test_one_asset_is_not_success(self):
        self.m['assets'].pop()
        self.assertEqual(compile_bounded(self.d,self.m)['status'],'blocked')
if __name__=='__main__':unittest.main()
