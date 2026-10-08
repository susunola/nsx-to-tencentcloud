#!/usr/bin/env python3
"""Offline, conservative NSX Policy snapshot to Tencent Cloud review compiler."""
import argparse, csv, ipaddress, json, pathlib, sys
from collections import Counter
from output_io import write_json, invalidate

from validation import validate_mapping, validate_snapshot, read_json, strings, object_value, integer

class Blocked(ValueError):
    pass

def net(value):
    return ipaddress.ip_network(value, strict=True)

def compile_snapshot(data, mapping, limit=200):
    integer(limit, 'rule budget')
    validate_mapping(mapping)
    validate_snapshot(data)
    assets = mapping['assets']
    groups = {g['path']: g for g in data['groups']}
    services = {s['path']: s for s in data['services']}
    issues, matrix, policies = [], [], {}
    if len({a['id'] for a in assets}) != len(assets):
        raise ValueError('Duplicate asset id')
    if len({a['security_group_id'] for a in assets}) != len(assets):
        raise ValueError('Use a dedicated target security group per asset in this version')
    all_old = []
    for a in assets:
        if not a['old_ips'] or not a['new_ips']:
            raise ValueError('Each asset needs old_ips and new_ips')
        for value in a['old_ips'] + a['new_ips']:
            ipaddress.ip_address(value)
        all_old.extend(a['old_ips'])
        policies[a['security_group_id']] = {'Ingress': [], 'Egress': []}
    if len(all_old) != len(set(all_old)):
        raise ValueError('Duplicate old IP; overlapping address spaces are unsupported')
    address_map = {str(net(k)): str(net(v)) for k, v in mapping.get('address_map', {}).items()}
    for a in assets:
        if len(a['old_ips']) != len(a['new_ips']):
            raise ValueError('old_ips/new_ips must be positionally paired')
        address_map.update((str(net(k)), str(net(v))) for k, v in zip(a['old_ips'], a['new_ips']))
    retain = {str(net(v)) for v in mapping.get('retain_addresses', [])}

    def old_addresses(refs):
        out = []
        if not refs:
            raise Blocked('Empty endpoint/scope is ambiguous')
        for ref in refs:
            if ref == 'ANY':
                out += ['0.0.0.0/0', '::/0']
            elif ref in groups:
                g = groups[ref]
                if not g.get('members_complete'):
                    raise Blocked('Group requires complete resolved IP membership: ' + ref)
                if not g.get('members'):
                    raise Blocked('Empty group: ' + ref)
                out += g['members']
            elif ref.startswith('/'):
                raise Blocked('Unresolved group: ' + ref)
            else:
                net(ref)
                out.append(ref)
        return list(dict.fromkeys(out))

    def translate(values):
        out = []
        for value in values:
            n = net(value)
            if n.prefixlen == 0 or str(n) in retain:
                out.append(str(n)); continue
            replacement = address_map.get(str(n))
            if replacement is None:
                raise Blocked('Missing explicit address/CIDR mapping: ' + value)
            target = net(replacement)
            if n.version != target.version or n.num_addresses != target.num_addresses:
                raise Blocked('Mapping changes address family or address-set size: ' + value)
            out.append(str(target))
        return list(dict.fromkeys(out))

    def contains(values, ip):
        addr = ipaddress.ip_address(ip)
        return any(addr.version == net(v).version and addr in net(v) for v in values)

    def service_entries(rule):
        entries = list(rule.get('service_entries', []))
        refs = rule.get('services', [])
        if refs == ['ANY'] and not entries:
            return [('ALL', None)]
        if 'ANY' in refs:
            raise Blocked('Mixed ANY service')
        for ref in refs:
            if ref not in services:
                raise Blocked('Unresolved service: ' + ref)
            entries += services[ref]['service_entries']
        out = []
        for e in entries:
            object_value(e, 'service entry')
            strings(e.get('source_ports', []), 'source_ports')
            strings(e.get('destination_ports', []), 'destination_ports')
            if e.get('resource_type') != 'L4PortSetServiceEntry' or e.get('source_ports'):
                raise Blocked('Unsupported service type or source-port restriction')
            protocol = e.get('l4_protocol')
            if protocol not in ('TCP', 'UDP'):
                raise Blocked('Unsupported protocol')
            for port in e.get('destination_ports') or ['1-65535']:
                parts = port.split('-')
                if len(parts) > 2 or not all(p.isdigit() and 1 <= int(p) <= 65535 for p in parts) or int(parts[0]) > int(parts[-1]):
                    raise Blocked('Invalid destination port: ' + port)
                out.append((protocol, port))
        if not out:
            raise Blocked('Empty service')
        return list(dict.fromkeys(out))

    # Explicit effective order is required; source collector must resolve categories/policy order.
    rules = data['rules']
    orders = [r['effective_order'] for r in rules]
    if len(set(orders)) != len(orders):
        raise ValueError('Duplicate effective_order')
    for r in sorted(rules, key=lambda r: r['effective_order']):
        rid = r.get('path', r.get('id', '?'))
        if r.get('disabled'):
            issues.append({'rule': rid, 'severity': 'info', 'reason': 'Disabled rule skipped'}); continue
        try:
            for flag in ('sources_excluded', 'destinations_excluded'):
                if r.get(flag): raise Blocked('Negated groups unsupported')
            if r.get('profiles', ['ANY']) not in ([], ['ANY']):
                raise Blocked('L7/context profiles unsupported')
            if r.get('stateful') is not True:
                raise Blocked('Explicit effective stateful=true required')
            if r.get('action') not in ('ALLOW', 'DROP'):
                raise Blocked('Only ALLOW/DROP supported')
            if r.get('direction') not in ('IN', 'OUT', 'IN_OUT'):
                raise Blocked('Explicit effective direction required')
            if r.get('ip_protocol') not in ('IPV4', 'IPV6', 'IPV4_IPV6'):
                raise Blocked('Explicit ip_protocol required')
            src, dst, scope = [old_addresses(r[k]) for k in ('source_groups', 'destination_groups', 'scope')]
            versions = {'IPV4': [4], 'IPV6': [6], 'IPV4_IPV6': [4, 6]}[r['ip_protocol']]
            src = [v for v in src if net(v).version in versions]
            dst = [v for v in dst if net(v).version in versions]
            new_src, new_dst = translate(src), translate(dst)
            svc = service_entries(r)
            pending = []
            pending_counts = Counter()
            for a in assets:
                scoped = [ip for ip in a['old_ips'] if contains(scope, ip)]
                if not scoped: continue
                if len(scoped) != len(a['old_ips']):
                    raise Blocked('Partial NIC scope requires separate per-NIC mapping: ' + a['id'])
                for direction, local, peers in [('Ingress', dst, new_src), ('Egress', src, new_dst)]:
                    if (direction == 'Ingress' and r['direction'] == 'OUT') or (direction == 'Egress' and r['direction'] == 'IN'): continue
                    selected = [ip for ip in a['old_ips'] if contains(local, ip)]
                    if not selected: continue
                    if len(selected) != len(a['old_ips']):
                        raise Blocked('Partial local address match: ' + a['id'])
                    for peer in peers:
                        for protocol, port in svc:
                            p = {'Protocol': protocol, 'Action': 'ACCEPT' if r['action'] == 'ALLOW' else 'DROP', 'PolicyDescription': ('NSX ' + rid)[-100:]}
                            p['CidrBlock' if net(peer).version == 4 else 'Ipv6CidrBlock'] = peer
                            if port: p['Port'] = port
                            pending.append((a['security_group_id'], direction, p))
                            if len(pending) > 100000:
                                raise Blocked('Rule expansion exceeds 100000 candidate limit')
                            key = (a['security_group_id'], direction)
                            pending_counts[key] += 1
                            if len(policies[key[0]][direction]) + pending_counts[key] > limit:
                                raise Blocked('Rule expansion exceeds configured per-direction budget')
            if not pending: raise Blocked('No mapped enforcement endpoint; review transit/unmigrated scope')
            for sg, direction, p in pending:
                policies[sg][direction].append(p)
            matrix.append({'rule': rid, 'order': r['effective_order'], 'source': new_src, 'destination': new_dst, 'services': svc, 'scope': r['scope'], 'direction': r['direction'], 'action': r['action'], 'logged': r.get('logged', False)})
            if r.get('logged'):
                issues.append({'rule': rid, 'severity': 'warning', 'reason': 'NSX per-rule logging is not preserved'})
        except (Blocked, ValueError) as e:
            issues.append({'rule': rid, 'severity': 'error', 'reason': str(e)})
    for sg, directions in policies.items():
        for direction, entries in directions.items():
            if len(entries) > limit:
                issues.append({'rule': sg, 'severity': 'error', 'reason': f'{direction}: {len(entries)} exceeds configured budget {limit}'})
            for i, p in enumerate(entries): p['PolicyIndex'] = i
    ready = not any(i['severity'] == 'error' for i in issues)
    templates = {'addresses': sorted({p.get('CidrBlock', p.get('Ipv6CidrBlock')) for d in policies.values() for es in d.values() for p in es}), 'services': sorted({p['Protocol'] + (':' + p['Port'] if 'Port' in p else '') for d in policies.values() for es in d.values() for p in es})}
    return {'provenance': data.get('provenance', {}), 'status': 'review_required' if ready else 'blocked', 'issues': issues, 'cloud_firewall_review': matrix, 'parameter_template_candidates': templates, 'security_group_requests': [{'SecurityGroupId': sg, 'SecurityGroupPolicySet': directions} for sg, directions in policies.items()] if ready else [], 'group_inventory': data['groups']}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', required=True); p.add_argument('--mapping', required=True)
    p.add_argument('--out', required=True); p.add_argument('--rule-budget', type=int, default=200)
    a = p.parse_args()
    try:
        result = compile_snapshot(read_json(a.snapshot), read_json(a.mapping), a.rule_budget)
        out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
        write_json(out / 'plan.json', result)
        with (out / 'issues.csv').open('w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['rule', 'severity', 'reason']); w.writeheader(); w.writerows(result['issues'])
        print(result['status'] + ': ' + str(out / 'plan.json'))
        return 2 if result['status'] == 'blocked' else 0
    except (ValueError, KeyError, TypeError, OSError) as e:
        try:
            invalidate(pathlib.Path(a.out) / 'plan.json', str(e))
        except OSError as output_error:
            print('Could not invalidate output: ' + str(output_error), file=sys.stderr)
        print('Invalid input: ' + str(e), file=sys.stderr); return 1
if __name__ == '__main__': sys.exit(main())
