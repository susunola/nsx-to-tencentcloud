"""Small independent first-match simulator for the known two-VM demo only."""
import ipaddress, json, pathlib
ROOT=pathlib.Path(__file__).parent
plan=json.loads((ROOT/'result/plan.json').read_text())
requests={r['SecurityGroupId']:r['SecurityGroupPolicySet'] for r in plan['security_group_requests']}
def allows(sg,direction,peer,protocol,port):
    for rule in requests[sg][direction]:
        cidr=rule.get('CidrBlock')
        if not cidr or ipaddress.ip_address(peer) not in ipaddress.ip_network(cidr):continue
        if rule['Protocol'] not in ('ALL',protocol):continue
        if rule['Protocol']!='ALL':
            parts=rule['Port'].split('-')
            if not int(parts[0])<=port<=int(parts[-1]):continue
        return rule['Action']=='ACCEPT'
    return False
cases=[]
for source,target,src_sg,dst_sg in [('10.0.1.11','10.0.2.21','sg-demo-a','sg-demo-b'),('10.0.2.21','10.0.1.11','sg-demo-b','sg-demo-a')]:
    for protocol,port in [('TCP',445),('TCP',22),('TCP',443),('UDP',445)]:
        expected=source=='10.0.1.11' and protocol=='TCP' and port==445
        actual=allows(src_sg,'Egress',target,protocol,port) and allows(dst_sg,'Ingress',source,protocol,port)
        cases.append(dict(source=source,destination=target,protocol=protocol,port=port,expected=expected,actual=actual,passed=expected==actual))
assert all(c['passed'] for c in cases)
(ROOT/'connectivity-check.json').write_text(json.dumps({'scope':'Offline demo only; not real network probes or general equivalence proof','cases':cases},indent=2)+'\n')
print(f'{len(cases)} offline connectivity cases passed')
