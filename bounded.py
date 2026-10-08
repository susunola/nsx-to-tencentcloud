"""Compile a deliberately bounded IPv4 TCP/UDP endpoint matrix, not a full migration."""
import ipaddress
from validation import validate_mapping, validate_snapshot, integer

CATEGORIES = ['Emergency', 'Infrastructure', 'Environment', 'Application']

def compile_bounded(data, mapping, limit=200):
    validate_mapping(mapping); validate_snapshot(data); integer(limit, 'rule budget')
    assets = mapping['assets']
    issues = []
    def blocked(reason):
        return {'status':'blocked','issues':[{'rule':'bounded','severity':'error','reason':reason}], 'security_group_requests':[]}
    if len(assets)>64: return blocked('Bounded mode supports at most 64 assets')
    if any(len(a['old_ips'])!=1 or len(a['new_ips'])!=1 or ipaddress.ip_address(a['old_ips'][0]).version!=4 for a in assets):
        return blocked('Bounded mode requires one IPv4 address per asset')
    groups = {g['path']:g for g in data['groups']}
    services = {s['path']:s for s in data['services']}
    rules = sorted(data['rules'],key=lambda r:r['effective_order'])
    if len({r['effective_order'] for r in rules})!=len(rules):return blocked('Duplicate effective order')
    if len(rules)>2000:return blocked('Bounded mode supports at most 2000 source rules')
    resolved=[];boundaries={'TCP':{1,65536},'UDP':{1,65536}}
    def addresses(refs):
        values=[]
        for ref in refs:
            if ref=='ANY': values.append(ipaddress.ip_network('0.0.0.0/0'))
            elif ref in groups:
                g=groups[ref]
                if g.get('members_complete') is not True:raise ValueError('Incomplete group '+ref)
                values.extend(ipaddress.ip_network(v) for v in g.get('members',[]))
            else:values.append(ipaddress.ip_network(ref))
        return values
    try:
        previous=-1
        for r in rules:
            if r.get('disabled'):continue
            category=r.get('category')
            if category not in CATEGORIES:raise ValueError('Explicit supported category required')
            pos=CATEGORIES.index(category)
            if pos<previous:raise ValueError('Category order is inconsistent')
            previous=pos
            if r.get('stateful') is not True:raise ValueError('Stateful rules required')
            if r.get('ip_protocol') not in ('IPV4','IPV4_IPV6'):raise ValueError('IPv4 rules required')
            if r.get('direction') not in ('IN','OUT','IN_OUT'):raise ValueError('Explicit direction required')
            if r.get('profiles', ['ANY']) not in ([],['ANY']):raise ValueError('L7 profiles unsupported')
            if r['action'] not in ('ALLOW','DROP','JUMP_TO_APPLICATION'):raise ValueError('Unsupported action')
            if r['action']=='JUMP_TO_APPLICATION' and category!='Environment':raise ValueError('Jump only valid in Environment')
            entry={'rule':r,'src':addresses(r['source_groups']),'dst':addresses(r['destination_groups']),'scope':addresses(r['scope']),'ranges':{'TCP':[],'UDP':[]}}
            if r.get('services')==['ANY'] and not r.get('service_entries'):
                entry['ranges']={'TCP':[(1,65535)],'UDP':[(1,65535)]}
            else:
                es=list(r.get('service_entries',[]))
                for ref in r.get('services',[]):
                    if ref not in services:raise ValueError('Unresolved service '+ref)
                    es+=services[ref]['service_entries']
                if not es:raise ValueError('Empty service')
                for e in es:
                    if e.get('resource_type')!='L4PortSetServiceEntry' or e.get('source_ports'):raise ValueError('Unsupported service/source ports')
                    proto=e.get('l4_protocol')
                    if proto not in boundaries:raise ValueError('Only TCP/UDP supported')
                    ports=e.get('destination_ports') or ['1-65535']
                    if not isinstance(ports,list):raise ValueError('Ports must be array')
                    for p in ports:
                        if not isinstance(p,str):raise ValueError('Port must be string')
                        pair=p.split('-')
                        if len(pair)>2 or not all(x.isdigit() for x in pair):raise ValueError('Invalid port')
                        lo,hi=int(pair[0]),int(pair[-1])
                        if not 1<=lo<=hi<=65535:raise ValueError('Invalid port range')
                        entry['ranges'][proto].append((lo,hi))
                        boundaries[proto].update([lo,hi+1])
            if r.get('logged'):issues.append({'rule':r.get('path','?'),'severity':'warning','reason':'Per-rule logging not preserved'})
            resolved.append(entry)
        if sum(len(x) for x in boundaries.values())>1024:raise ValueError('Too many port partitions')
    except (ValueError,KeyError,TypeError) as e:return blocked(str(e))
    def contains(nets,ip):return any(ip.version==n.version and ip in n for n in nets)
    def decide(local,src,dst,direction,proto,port):
        jump=False;trace=[]
        for e in resolved:
            r=e['rule']
            if jump and r['category']!='Application':continue
            if r['direction'] not in (direction,'IN_OUT'):continue
            if not contains(e['scope'],local):continue
            source=contains(e['src'],src);dest=contains(e['dst'],dst)
            if r.get('sources_excluded'):source=not source
            if r.get('destinations_excluded'):dest=not dest
            if not source or not dest or not any(lo<=port<=hi for lo,hi in e['ranges'][proto]):continue
            trace.append(r.get('path',r.get('id','?')))
            if r['action']=='JUMP_TO_APPLICATION':jump=True;continue
            return r['action']=='ALLOW',trace
        return False,trace+['implicit-default-deny']
    policies={a['security_group_id']:{'Ingress':[],'Egress':[]} for a in assets}
    connections=[];checks=0
    # Conservative candidate limit for the evaluator's total work.
    work=len(assets)*(len(assets)-1)*sum(len(v)-1 for v in boundaries.values())*max(1,len(resolved))*2
    if work>5000000:return blocked('Evaluation work exceeds 5 million rule checks')
    for a in assets:
        for b in assets:
            if a['id']==b['id']:continue
            src=ipaddress.ip_address(a['old_ips'][0]);dst=ipaddress.ip_address(b['old_ips'][0])
            for proto in ['TCP','UDP']:
                points=sorted(boundaries[proto]);allowed=[]
                for lo,stop in zip(points,points[1:]):
                    out,tout=decide(src,src,dst,'OUT',proto,lo)
                    inc,tin=decide(dst,src,dst,'IN',proto,lo);checks+=1
                    if out and inc:
                        if allowed and allowed[-1]['end']+1==lo and allowed[-1]['trace']==[tout,tin]:allowed[-1]['end']=stop-1
                        else:allowed.append({'start':lo,'end':stop-1,'trace':[tout,tin]})
                for segment in allowed:
                    # Tencent SG port zero is outside this tool's supported target representation.
                    if segment['start']==0:return blocked('Port zero allowed in bounded source; cannot represent safely')
                    port=str(segment['start']) if segment['start']==segment['end'] else f"{segment['start']}-{segment['end']}"
                    for asset,direction,peer in [(a,'Egress',b),(b,'Ingress',a)]:
                        es=policies[asset['security_group_id']][direction]
                        es.append({'Protocol':proto,'Port':port,'CidrBlock':peer['new_ips'][0]+'/32','Action':'ACCEPT','PolicyDescription':'Bounded '+a['id']+' -> '+b['id']})
                        if len(es)+1>limit:return blocked('Bounded target rule budget exceeded')
                    connections.append({'source':a['id'],'destination':b['id'],'protocol':proto,'port':port,'source_rule_trace':segment['trace']})
    for directions in policies.values():
        for entries in directions.values():
            entries.append({'Protocol':'ALL','CidrBlock':'0.0.0.0/0','Action':'DROP','PolicyDescription':'Bounded domain default deny'})
            if len(entries)>limit:return blocked('Bounded target rule budget exceeded')
            for i,p in enumerate(entries):p['PolicyIndex']=i
    return {'status':'bounded_review_required','issues':issues,'coverage':{'domain':'distinct mapped single-IPv4 VM pairs; TCP/UDP destination ports 1..65535','default_assumption':'unmatched source traffic denied at each endpoint','outside_domain':'denied in target; this is intentional isolation, NOT full NSX equivalence','port_partitions_evaluated':checks},'connections':connections,'security_group_requests':[{'SecurityGroupId':sg,'SecurityGroupPolicySet':d} for sg,d in policies.items()]}
