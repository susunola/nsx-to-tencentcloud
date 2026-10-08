"""Repeatable public-fixture trial; mapped IPv4 VM pairs and new connections only."""
import ipaddress, json, pathlib, sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from adapt import from_analyzer
from migrate import compile_snapshot
from bounded import compile_bounded
from output_io import write_json
ROOT=pathlib.Path(__file__).parent

def hit(addresses, value):
    addr=ipaddress.ip_address(value)
    for x in addresses:
        if x=='ANY':return True
        if '-' in x:
            lo,hi=map(ipaddress.ip_address,x.split('-'))
            if addr.version==lo.version and int(lo)<=int(addr)<=int(hi):return True
        else:
            n=ipaddress.ip_network(x)
            if addr.version==n.version and addr in n:return True
    return False

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
    entry_paths={e['path']:e for es in services.values() for e in es if e.get('path')}
    def expand_entries(r):
        leaves=[]
        def entry(e,stack):
            if e.get('resource_type')!='NestedServiceServiceEntry':leaves.append(e);return
            ref(e['nested_service_path'],stack)
        def ref(path,stack):
            if path in stack or len(stack)>16:raise ValueError('Verifier service cycle/depth')
            if path in services:
                for e in services[path]:entry(e,stack+[path])
            else:entry(entry_paths[path],stack+[path])
        for path in r.get('services') or []:
            if path!='ANY':ref(path,[])
        for e in r.get('service_entries') or []:entry(e,[])
        return leaves
    def endpoint(refs,ip):
        return any(ref=='ANY' or hit(groups.get(ref,[ref]),ip) for ref in refs)
    rules=sorted(snapshot['rules'],key=lambda r:r['effective_order'])
    def source_decision(local,src,dst,direction,proto,port):
        jumped=False
        for r in rules:
            if jumped and r.get('category')!='Application':continue
            if r.get('disabled') or r['direction'] not in (direction,'IN_OUT'):continue
            family=ipaddress.ip_address(src).version
            if r['ip_protocol']=='IPV4' and family!=4:continue
            if r['ip_protocol']=='IPV6' and family!=6:continue
            source_match=endpoint(r['source_groups'],src)
            destination_match=endpoint(r['destination_groups'],dst)
            if r.get('sources_excluded'):source_match=not source_match
            if r.get('destinations_excluded'):destination_match=not destination_match
            if not endpoint(r['scope'],local) or not source_match or not destination_match:continue
            entries=expand_entries(r)
            if r.get('services')!=['ANY'] and not port_match(entries,proto,port):continue
            if r['action']=='JUMP_TO_APPLICATION':
                jumped=True;continue
            return r['action']=='ALLOW'
        return False # Trial assumption: unmatched traffic denied at each endpoint.
    sg={r['SecurityGroupId']:r['SecurityGroupPolicySet'] for r in plan['security_group_requests']}
    def target_decision(asset,direction,peer,proto,port):
        for r in sg[asset['security_group_id']][direction]:
            if not hit([r.get('CidrBlock',r.get('Ipv6CidrBlock'))],peer):continue
            if r['Protocol']!='ALL':
                if r['Protocol']!=proto:continue
                parts=r['Port'].split('-')
                if not int(parts[0])<=port<=int(parts[-1]):continue
            return r['Action']=='ACCEPT'
        return False
    ports={0,1,22,53,80,443,445,3306,65535}
    for r in rules:
        if r.get('disabled'):continue
        entries=expand_entries(r)
        for e in entries:
            for p in e.get('destination_ports') or ['1-65535']:
                for boundary in map(int,p.split('-')):
                    ports.update(x for x in [boundary-1,boundary,boundary+1] if 0<=x<=65535)
    checked=0;mismatches=[]
    for a in mapping['assets']:
        for b in mapping['assets']:
            if a['id']==b['id']:continue
            if ipaddress.ip_address(a['old_ips'][0]).version!=ipaddress.ip_address(b['old_ips'][0]).version:continue
            for proto in ['TCP','UDP']:
                for port in sorted(p for p in ports if p>=minimum_port):
                    old_a,old_b=a['old_ips'][0],b['old_ips'][0]
                    expected=source_decision(old_a,old_a,old_b,'OUT',proto,port) and source_decision(old_b,old_a,old_b,'IN',proto,port)
                    actual=target_decision(a,'Egress',b['new_ips'][0],proto,port) and target_decision(b,'Ingress',a['new_ips'][0],proto,port)
                    checked+=1
                    if actual!=expected:mismatches.append({'source':a['id'],'destination':b['id'],'protocol':proto,'port':port,'expected':expected,'actual':actual})
    return checked,mismatches

def convert_mode(compiler, snapshot, mapping):
    try:
        return compiler(snapshot,mapping)
    except (ValueError,KeyError,TypeError) as e:
        return {'status':'blocked','security_group_requests':[],
                'issues':[{'rule':'input','severity':'error','reason':str(e)}],
                'failure_phase':'compiler_input_validation'}

def run(write_report=True, quiet=False):
    reports=[]
    paths=sorted(ROOT.glob('Example*.json'))
    if len(paths)!=20:raise ValueError(f'Batch requires exactly 20 public inputs, got {len(paths)}')
    for path in paths:
        report={'fixture':path.name}
        try:
            data=json.loads(path.read_text()); resource=data['domains'][0]['resources']
            mapping={'assets':[{'id':vm['external_id'],'old_ips':[f'192.0.2.{i+1}'],'new_ips':[f'198.51.100.{i+1}'],'security_group_id':f'sg-trial-{i+1}'} for i,vm in enumerate(data.get('virtual_machines') or [])]}
            manifest={'export_complete':True,'exclude_list_reviewed':True,'captured_at':'public generated fixture; synthetic trial','policy_order':[p.get('id',p.get('display_name')) for p in resource['security_policies']],'rule_arrays_in_effective_order':True,'allow_vm_members_from_mapping':True,'rule_defaults':{'stateful':True,'direction':'IN_OUT','ip_protocol':'IPV4'}}
            report.update(vms=len(mapping['assets']),groups=len(resource['groups']),rules=sum(len(p.get('rules') or []) for p in resource['security_policies']))
            snapshot=from_analyzer(data,mapping,manifest)
        except (ValueError,KeyError,TypeError) as e:
            report.update(status='adaptation_blocked',bounded_status='adaptation_blocked',issues=[str(e)])
            if write_report:
                for name in ['plan.json','bounded-plan.json']:
                    write_json(ROOT/'results'/path.stem/name,{'status':'blocked','security_group_requests':[],'issues':[str(e)]})
            reports.append(report);continue
        for prefix,compiler,filename in [('',compile_snapshot,'plan.json'),('bounded_',compile_bounded,'bounded-plan.json')]:
            plan=convert_mode(compiler,snapshot,mapping)
            report[prefix+'status']=plan['status'];report[prefix+'issues']=plan['issues']
            if write_report:write_json(ROOT/'results'/path.stem/filename,plan)
            if plan['status']=='blocked':
                if plan['security_group_requests']:raise AssertionError('Blocked plan contains requests')
                continue
            if prefix:
                report['bounded_partitions']=plan['coverage']['port_partitions_evaluated']
                report['bounded_connections']=len(plan['connections'])
            try:
                count,mismatches=evaluate(snapshot,plan,mapping,minimum_port=1 if prefix else 0)
                report[prefix+'connection_cases']=count;report[prefix+'mismatches']=mismatches
                report[prefix+'generated_rules']=sum(len(es) for r in plan['security_group_requests'] for es in r['SecurityGroupPolicySet'].values())
                if mismatches:report[prefix+'verification_status']='mismatch'
                elif count==0:report[prefix+'verification_status']='no_comparable_connections'
                else:report[prefix+'verification_status']='matched'
            except (ValueError,KeyError,TypeError) as e:
                report[prefix+'verification_status']='error'
                report[prefix+'verification_error']=str(e)
        reports.append(report)
    summary={'inputs':len(reports),'ordinary_converted':sum(r['status']=='review_required' for r in reports),
             'bounded_converted':sum(r['bounded_status']=='bounded_review_required' for r in reports),
             'connection_checks':sum(r.get('connection_cases',0)+r.get('bounded_connection_cases',0) for r in reports),
             'mismatches':sum(len(r.get('mismatches',[]))+len(r.get('bounded_mismatches',[])) for r in reports),
             'verification_errors':sum(r.get('verification_status')=='error' or r.get('bounded_verification_status')=='error' for r in reports)}
    if write_report:write_json(ROOT/'report.json',{'limitations':'Synthetic single-IP mappings and explicit defaults. Mapped VM pairs only; sampled TCP/UDP new connections. Not general equivalence or live validation.','summary':summary,'fixtures':reports})
    if not quiet:
        for r in reports:print(r['fixture'],r['status'],r['bounded_status'],r.get('verification_status'),r.get('bounded_verification_status'))
        print(json.dumps(summary))
    return reports
if __name__=='__main__':
    reports=run()
    if any(r.get('mismatches') or r.get('bounded_mismatches') or r.get('verification_status')=='error' or r.get('bounded_verification_status')=='error' for r in reports):sys.exit(1)
