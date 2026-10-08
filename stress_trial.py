"""Seeded differential trial against an independent finite-domain evaluator."""
import ipaddress,json,random
from bounded import compile_bounded

def trial(seeds=40, batch_size=20):
    checks=0
    for seed in range(seeds):
        rng=random.Random(seed);v6=seed%2==1
        old=[f'2001:db8::{i+1}' if v6 else f'192.0.2.{i+1}' for i in range(5)]
        new=[f'2001:db8:1::{i+1}' if v6 else f'198.51.100.{i+1}' for i in range(5)]
        mapping={'assets':[{'id':str(i),'old_ips':[old[i]],'new_ips':[new[i]],'security_group_id':f'sg-{i}'} for i in range(5)]}
        memberships={f'/g/{i}':rng.sample(old,rng.randint(1,5)) for i in range(4)}
        snapshot={'groups':[{'path':key,'members':values,'members_complete':True} for key,values in memberships.items()],'services':[],'rules':[]}
        options=['ANY']+list(memberships)
        for i in range(8):
            category='Environment' if i<3 else 'Application'
            action=rng.choice(['ALLOW','DROP','JUMP_TO_APPLICATION'] if i<3 else ['ALLOW','DROP'])
            lo,hi=rng.choice([(22,22),(80,80),(100,105),(443,443),(1,65535)])
            snapshot['rules'].append({'path':f'/r/{i}','effective_order':i,'category':category,'stateful':True,'direction':rng.choice(['IN','OUT','IN_OUT']),'ip_protocol':rng.choice(['IPV4_IPV6','IPV4','IPV6']),'action':action,'source_groups':[rng.choice(options)],'destination_groups':[rng.choice(options)],'scope':[rng.choice(options)],'sources_excluded':rng.choice([True,False]),'destinations_excluded':rng.choice([True,False]),'services':[],'service_entries':[{'resource_type':'L4PortSetServiceEntry','l4_protocol':rng.choice(['TCP','UDP']),'destination_ports':[str(lo) if lo==hi else f'{lo}-{hi}']}]})
        plan=compile_bounded(snapshot,mapping)
        if plan['status']!='bounded_review_required':raise AssertionError(f'seed {seed}: {plan}')
        # Independent source evaluator: direct fixture membership, explicit index jump.
        def member(ref,ip):return ref=='ANY' or ip in memberships[ref]
        def source(src,dst,local,direction,proto,port):
            i=0
            while i<len(snapshot['rules']):
                r=snapshot['rules'][i];i+=1
                if r['ip_protocol']!=('IPV6' if v6 else 'IPV4') and r['ip_protocol']!='IPV4_IPV6':continue
                if r['direction'] not in [direction,'IN_OUT']:continue
                if not member(r['scope'][0],local):continue
                if member(r['source_groups'][0],src)==r['sources_excluded']:continue
                if member(r['destination_groups'][0],dst)==r['destinations_excluded']:continue
                e=r['service_entries'][0];parts=e['destination_ports'][0].split('-')
                if e['l4_protocol']!=proto or not int(parts[0])<=port<=int(parts[-1]):continue
                if r['action']=='JUMP_TO_APPLICATION':i=3;continue
                return r['action']=='ALLOW'
            return False
        requests={req['SecurityGroupId']:req['SecurityGroupPolicySet'] for req in plan['security_group_requests']}
        def target(index,direction,peer,proto,port):
            for r in requests[f'sg-{index}'][direction]:
                n=ipaddress.ip_network(r.get('CidrBlock',r.get('Ipv6CidrBlock')))
                if ipaddress.ip_address(peer) not in n:continue
                if r['Protocol']!='ALL':
                    parts=r['Port'].split('-')
                    if r['Protocol']!=proto or not int(parts[0])<=port<=int(parts[-1]):continue
                return r['Action']=='ACCEPT'
            return False
        ports=[1,2,21,22,23,79,80,81,99,100,101,104,105,106,442,443,444,65534,65535]
        for a in range(5):
            for b in range(5):
                if a==b:continue
                for proto in ['TCP','UDP']:
                    for port in ports:
                        expected=source(old[a],old[b],old[a],'OUT',proto,port) and source(old[a],old[b],old[b],'IN',proto,port)
                        actual=target(a,'Egress',new[b],proto,port) and target(b,'Ingress',new[a],proto,port)
                        checks+=1
                        if expected!=actual:raise AssertionError(f'Connectivity mismatch seed={seed} {a}->{b} {proto}/{port}')
    batches=[{'batch':start//batch_size+1,'seed_start':start,'seed_end':min(start+batch_size,seeds)-1,'configurations':min(batch_size,seeds-start),'connection_checks':min(batch_size,seeds-start)*760,'mismatches':0} for start in range(0,seeds,batch_size)]
    return {'batch_size':batch_size,'batch_count':len(batches),'batches':batches,'generated_configurations':seeds,'ipv4_configurations':(seeds+1)//2,'ipv6_configurations':seeds//2,'connection_checks':checks,'mismatches':0,'coverage':'Seeded five-asset single-IP fixtures; negation, jumps, scopes, direction, family filters, TCP/UDP port boundaries. Finite-domain offline testing only.'}
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seeds',type=int,default=40)
    args=parser.parse_args()
    if not 1<=args.seeds<=10000:parser.error('--seeds must be between 1 and 10000')
    print(json.dumps(trial(args.seeds),indent=2))
