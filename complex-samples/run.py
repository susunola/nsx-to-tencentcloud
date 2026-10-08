"""Repeatable public-fixture trial; mapped IPv4 VM pairs and new connections only."""
import ipaddress, json, pathlib, sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from adapt import from_analyzer
from migrate import compile_snapshot
from bounded import compile_bounded
ROOT=pathlib.Path(__file__).parent

def hit(addresses, value):
    return any(x=='ANY' or ipaddress.ip_address(value) in ipaddress.ip_network(x) for x in addresses)

def port_match(entries, protocol, port):
    for e in entries:
        if e.get('l4_protocol')!=protocol:continue
        for p in e.get('destination_ports') or ['1-65535']:
            parts=p.split('-')
            if int(parts[0])<=port<=int(parts[-1]):return True
    return False

def evaluate(snapshot, plan, mapping, minimum_port=0):
    groups={g['path']:g['members'] for g in snapshot['groups']}
    services={s['path']:s['service_entries'] for s in snapshot['services']}
    def endpoint(refs,ip):
        return any(ref=='ANY' or hit(groups.get(ref,[ref]),ip) for ref in refs)
    rules=sorted(snapshot['rules'],key=lambda r:r['effective_order'])
    def source_decision(local,src,dst,direction,proto,port):
        jumped=False
        for r in rules:
            if jumped and r.get('category')!='Application':continue
            if r.get('disabled') or r['direction'] not in (direction,'IN_OUT'):continue
            source_match=endpoint(r['source_groups'],src)
            destination_match=endpoint(r['destination_groups'],dst)
            if r.get('sources_excluded'):source_match=not source_match
            if r.get('destinations_excluded'):destination_match=not destination_match
            if not endpoint(r['scope'],local) or not source_match or not destination_match:continue
            entries=list(r.get('service_entries') or [])
            for ref in r.get('services') or []:
                if ref!='ANY':entries+=services[ref]
            if r.get('services')!=['ANY'] and not port_match(entries,proto,port):continue
            if r['action']=='JUMP_TO_APPLICATION':
                jumped=True;continue
            return r['action']=='ALLOW'
        return False # Trial assumption: unmatched traffic denied at each endpoint.
    sg={r['SecurityGroupId']:r['SecurityGroupPolicySet'] for r in plan['security_group_requests']}
    def target_decision(asset,direction,peer,proto,port):
        for r in sg[asset['security_group_id']][direction]:
            if not hit([r['CidrBlock']],peer):continue
            if r['Protocol']!='ALL':
                if r['Protocol']!=proto:continue
                parts=r['Port'].split('-')
                if not int(parts[0])<=port<=int(parts[-1]):continue
            return r['Action']=='ACCEPT'
        return False
    ports={0,1,22,53,80,443,445,3306,65535}
    for r in rules:
        entries=list(r.get('service_entries') or [])
        for ref in r.get('services') or []:
            if ref!='ANY':entries+=services[ref]
        for e in entries:
            for p in e.get('destination_ports') or ['1-65535']:
                for boundary in map(int,p.split('-')):
                    ports.update(x for x in [boundary-1,boundary,boundary+1] if 0<=x<=65535)
    checked=0;mismatches=[]
    for a in mapping['assets']:
        for b in mapping['assets']:
            if a['id']==b['id']:continue
            for proto in ['TCP','UDP']:
                for port in sorted(p for p in ports if p>=minimum_port):
                    old_a,old_b=a['old_ips'][0],b['old_ips'][0]
                    expected=source_decision(old_a,old_a,old_b,'OUT',proto,port) and source_decision(old_b,old_a,old_b,'IN',proto,port)
                    actual=target_decision(a,'Egress',b['new_ips'][0],proto,port) and target_decision(b,'Ingress',a['new_ips'][0],proto,port)
                    checked+=1
                    if actual!=expected:mismatches.append({'source':a['id'],'destination':b['id'],'protocol':proto,'port':port,'expected':expected,'actual':actual})
    return checked,mismatches

def run(write_report=True):
    reports=[]
    for path in sorted(ROOT.glob('*.json')):
        if path.name=='report.json':continue
        data=json.loads(path.read_text()); resource=data['domains'][0]['resources']
        mapping={'assets':[{'id':vm['external_id'],'old_ips':[f'192.0.2.{i+1}'],'new_ips':[f'198.51.100.{i+1}'],'security_group_id':f'sg-trial-{i+1}'} for i,vm in enumerate(data['virtual_machines'])]}
        manifest={'export_complete':True,'exclude_list_reviewed':True,'captured_at':'public generated fixture; synthetic trial','policy_order':[p.get('id',p.get('display_name')) for p in resource['security_policies']],'rule_arrays_in_effective_order':True,'allow_vm_members_from_mapping':True,'rule_defaults':{'stateful':True,'direction':'IN_OUT','ip_protocol':'IPV4'}}
        report={'fixture':path.name,'vms':len(mapping['assets']),'groups':len(resource['groups']),'rules':sum(len(p.get('rules') or []) for p in resource['security_policies'])}
        try:
            snapshot=from_analyzer(data,mapping,manifest);plan=compile_snapshot(snapshot,mapping)
            report.update(status=plan['status'],issues=plan['issues'])
            bounded=compile_bounded(snapshot,mapping)
            report['bounded_status']=bounded['status']
            report['bounded_issues']=bounded['issues']
            if bounded['status']=='bounded_review_required':
                report['bounded_partitions']=bounded['coverage']['port_partitions_evaluated']
                report['bounded_connections']=len(bounded['connections'])
                count,mismatches=evaluate(snapshot,bounded,mapping,minimum_port=1)
                report.update(bounded_connection_cases=count,bounded_mismatches=mismatches)
                if write_report:
                    dest=ROOT/'results'/path.stem
                    dest.mkdir(parents=True,exist_ok=True)
                    (dest/'bounded-plan.json').write_text(json.dumps(bounded,indent=2)+'\n')
            if plan['status']=='review_required':
                count,mismatches=evaluate(snapshot,plan,mapping)
                report.update(connection_cases=count,mismatches=mismatches,generated_rules=sum(len(es) for r in plan['security_group_requests'] for es in r['SecurityGroupPolicySet'].values()))
            else:assert not plan['security_group_requests']
        except (ValueError,KeyError,TypeError) as e:
            report.update(status='adaptation_blocked',issues=[str(e)])
        reports.append(report)
    if write_report: (ROOT/'report.json').write_text(json.dumps({'limitations':'Synthetic single-IP mappings and explicit defaults. Mapped VM pairs only; TCP/UDP new connections with sampled port boundaries. Not general equivalence, tag-expression evaluation, or live cloud validation.','fixtures':reports},indent=2)+'\n')
    for r in reports:print(r['fixture'],r['status'],'cases',r.get('connection_cases',0),'mismatches',len(r.get('mismatches',[])))
    return reports
if __name__=='__main__':
    reports=run()
    if any(r.get('mismatches') or r.get('bounded_mismatches') for r in reports):sys.exit(1)
