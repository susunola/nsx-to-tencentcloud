#!/usr/bin/env python3
"""Normalize public analyzer JSON or AWS Labs NSX export directories."""
import argparse, copy, json, pathlib, sys
from output_io import write_json, invalidate
from validation import read_json, validate_mapping, booleans, object_value, integer

CATEGORIES = ['Ethernet', 'Emergency', 'Infrastructure', 'Environment', 'Application']

def read(path):
    return read_json(path)

def results(value):
    if isinstance(value, list): return value
    if not isinstance(value, dict) or not isinstance(value.get('results'), list):
        raise ValueError('Expected array or results array')
    if value.get('cursor'): raise ValueError('Unconsumed API cursor; incomplete export')
    return value['results']

def normalize(policies, groups, services, mapping, manifest, tags=None):
    validate_mapping(mapping)
    object_value(manifest, 'manifest')
    booleans(manifest, ['export_complete','exclude_list_reviewed','allow_vm_members_from_mapping','rule_arrays_in_effective_order'], 'manifest')
    if not manifest.get('export_complete') or not manifest.get('exclude_list_reviewed'):
        raise ValueError('Manifest must attest export_complete and exclude_list_reviewed')
    if manifest.get('excluded_asset_ids'):
        raise ValueError('DFW excluded assets require separate handling')
    if not manifest.get('captured_at'):
        raise ValueError('Manifest captured_at required')
    members = manifest.get('group_members', {})
    inventory = []
    by_id = {a['id']: a for a in mapping['assets']}
    for original in groups:
        g = copy.deepcopy(original)
        key = g.get('path')
        if not key: raise ValueError('Group path required')
        if key in members:
            entry = members[key]
            object_value(entry, 'group membership')
            booleans(entry, ['complete'], 'group membership')
            g.update(members=entry['ips'], members_complete=entry.get('complete', False))
        elif manifest.get('allow_vm_members_from_mapping') and g.get('vm_members') is not None:
            ips = []
            for vm in g['vm_members']:
                identity = vm.get('id', vm.get('external_id'))
                if identity not in by_id:
                    raise ValueError('VM member missing mapping: ' + str(identity))
                ips += by_id[identity]['old_ips']
            g.update(members=ips, members_complete=True)
        else:
            # Preserve unresolvable groups; compiler blocks when referenced.
            g.update(members=[], members_complete=False)
        inventory.append(g)
    if len({g['path'] for g in inventory}) != len(inventory):
        raise ValueError('Duplicate group paths')
    policy_ids = [p.get('id', p.get('display_name')) for p in policies]
    if len(set(policy_ids)) != len(policy_ids) or None in policy_ids:
        raise ValueError('Unique policy identities required')
    ordered = manifest.get('policy_order')
    if not isinstance(ordered, list) or len(ordered) != len(set(ordered)) or set(ordered) != set(policy_ids):
        raise ValueError('policy_order must explicitly list every policy exactly once')
    indexed = dict(zip(policy_ids, policies))
    previous = -1
    normalized_rules = []
    assumptions = manifest.get('rule_defaults', {})
    for pid in ordered:
        policy = indexed[pid]
        booleans(policy, ['stateful','disabled'], 'policy')
        if policy.get('disabled') is True:
            raise ValueError('Disabled policy requires explicit handling: ' + pid)
        category = policy.get('category')
        if category not in CATEGORIES or category == 'Ethernet':
            raise ValueError('Unsupported policy category: ' + str(category))
        category_order = CATEGORIES.index(category)
        if category_order < previous: raise ValueError('policy_order violates NSX category ordering')
        previous = category_order
        rule_list = list(policy.get('rules', []))
        if policy.get('default_rule'):
            raise ValueError('Separate default_rule requires explicit ordering in rules')
        if all('sequence_number' in r for r in rule_list):
            numbers = [r['sequence_number'] for r in rule_list]
            for number in numbers: integer(number, 'sequence_number')
            if len(numbers) != len(set(numbers)): raise ValueError('Ambiguous rule sequence in ' + pid)
            rule_list.sort(key=lambda r:r['sequence_number'])
        elif not manifest.get('rule_arrays_in_effective_order'):
            raise ValueError('Missing rule sequence; explicit ordered-array attestation needed')
        if not rule_list: raise ValueError('Missing/empty policy rules: ' + pid)
        for source in rule_list:
            r = copy.deepcopy(source)
            if 'scope' in r and not r['scope']:
                raise ValueError('Explicit empty scope must not inherit policy scope')
            r['path'] = r.get('path') or f"{pid}/rules/{r.get('id',r.get('rule_id',r.get('display_name')))}"
            r['effective_order'] = len(normalized_rules)
            r['category'] = category
            r['scope'] = r.get('scope') or policy.get('scope')
            for field in ('stateful', 'direction', 'ip_protocol'):
                if field not in r:
                    if field == 'stateful' and field in policy: r[field] = policy[field]
                    elif field in assumptions: r[field] = assumptions[field]
            r['services'] = r.get('services') or []
            r['service_entries'] = r.get('service_entries') or []
            normalized_rules.append(r)
    return {'groups':inventory, 'services':services, 'rules':normalized_rules,
            'provenance':{'captured_at':manifest['captured_at'], 'assumptions':assumptions,
                          'source_format':manifest.get('source_format'), 'tags':tags or []}}

def from_analyzer(data, mapping, manifest):
    domains = data.get('domains') or []
    if len(domains) != 1: raise ValueError('Exactly one domain supported')
    resource = domains[0]['resources']
    return normalize(resource['security_policies'], resource['groups'], data['services'], mapping, manifest)

def from_aws(directory, mapping, manifest):
    root = pathlib.Path(directory)
    files = manifest.get('files', {})
    def load(key, default): return read(root / files.get(key, default))
    policies = results(load('policies','dfw.json'))
    detail = load('rules','dfw_details.json')
    for policy in policies:
        if policy['id'] not in detail: raise ValueError('Missing detailed policy ' + policy['id'])
        policy['rules'] = results(detail[policy['id']])
    groups = results(load('groups','cgw-groups.json'))
    services = results(load('services','services.json'))
    tags_path = root / files.get('tags','tags.json')
    tags = read(tags_path) if tags_path.exists() else []
    return normalize(policies, groups, services, mapping, manifest, tags)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--format', choices=['analyzer','aws-export'], required=True)
    p.add_argument('--input', required=True); p.add_argument('--mapping', required=True)
    p.add_argument('--manifest', required=True); p.add_argument('--out', required=True)
    a = p.parse_args()
    try:
        mapping, manifest = read(a.mapping), read(a.manifest)
        output = from_analyzer(read(a.input),mapping,manifest) if a.format == 'analyzer' else from_aws(a.input,mapping,manifest)
        dest = pathlib.Path(a.out); dest.parent.mkdir(parents=True,exist_ok=True)
        write_json(dest, output)
        print(f"Normalized {len(output['rules'])} rules, {len(output['groups'])} groups")
        return 0
    except (KeyError, TypeError, ValueError, OSError) as e:
        try:
            invalidate(a.out, str(e))
        except OSError as output_error:
            print('Could not invalidate output: ' + str(output_error), file=sys.stderr)
        print('Adaptation blocked: '+str(e),file=sys.stderr); return 1
if __name__ == '__main__': sys.exit(main())
