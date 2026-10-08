"""Strict input validation shared by adapters and the policy compiler."""
import ipaddress
from addresses import networks
import json
import pathlib

MAX_INPUT_BYTES = 64 * 1024 * 1024

def object_value(value, label):
    if not isinstance(value, dict):
        raise ValueError(f'{label} must be an object')
    return value

def array(value, label):
    if not isinstance(value, list):
        raise ValueError(f'{label} must be an array')
    return value

def strings(value, label, nonempty=False):
    array(value, label)
    if nonempty and not value:
        raise ValueError(f'{label} must not be empty')
    if any(not isinstance(x, str) or not x.strip() for x in value):
        raise ValueError(f'{label} must contain nonempty strings')
    if 'ANY' in value and value != ['ANY']:
        raise ValueError(f'{label}: ANY must be the only entry')
    return value

def booleans(value, fields, label):
    for field in fields:
        if field in value and type(value[field]) is not bool:
            raise ValueError(f'{label}.{field} must be a JSON boolean')

def integer(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(f'{label} must be a nonnegative integer')

def unique_objects(values, key, label):
    array(values, label)
    seen = set()
    for item in values:
        object_value(item, label)
        identity = item.get(key)
        if not isinstance(identity, str) or not identity.strip():
            raise ValueError(f'{label}.{key} must be a nonempty string')
        if identity in seen:
            raise ValueError(f'Duplicate {label}.{key}: {identity}')
        seen.add(identity)

def validate_mapping(mapping):
    object_value(mapping, 'mapping')
    assets = mapping.get('assets')
    unique_objects(assets, 'id', 'assets')
    unique_objects(assets, 'security_group_id', 'assets')
    if not assets:
        raise ValueError('assets must not be empty')
    old_seen, new_seen = set(), set()
    pairs = {}
    for asset in assets:
        old = strings(asset.get('old_ips'), 'old_ips', True)
        new = strings(asset.get('new_ips'), 'new_ips', True)
        if len(old) != len(new):
            raise ValueError('old_ips/new_ips must be positionally paired')
        for source, target in zip(old, new):
            s, t = ipaddress.ip_address(source), ipaddress.ip_address(target)
            if s.version != t.version:
                raise ValueError('Asset mapping changes IP family')
            if str(s) in old_seen or str(t) in new_seen:
                raise ValueError('Duplicate old or new asset IP (including canonical aliases)')
            old_seen.add(str(s)); new_seen.add(str(t))
            pairs[str(ipaddress.ip_network(source))] = str(ipaddress.ip_network(target))
    explicit = object_value(mapping.get('address_map', {}), 'address_map')
    canonical = {}
    for source, target in explicit.items():
        s, t = ipaddress.ip_network(source, strict=True), ipaddress.ip_network(target, strict=True)
        if s.version != t.version or s.num_addresses != t.num_addresses:
            raise ValueError('Address mapping changes family or address-set size')
        key = str(s)
        if key in canonical or (key in pairs and pairs[key] != str(t)):
            raise ValueError('Duplicate or conflicting address_map entry: ' + key)
        canonical[key] = str(t)
    for value in strings(mapping.get('retain_addresses', []), 'retain_addresses'):
        n = ipaddress.ip_network(value, strict=True)
        for source, target in {**pairs, **canonical}.items():
            s, t = ipaddress.ip_network(source), ipaddress.ip_network(target)
            if s.version == n.version and s.overlaps(n) and s != t:
                raise ValueError('Retained range overlaps a changed address mapping: ' + value)
    # CIDR mappings must agree with asset mappings inside their range.
    for source, target in canonical.items():
        s, t = ipaddress.ip_network(source), ipaddress.ip_network(target)
        for old, new in pairs.items():
            o, n = ipaddress.ip_network(old), ipaddress.ip_network(new)
            if o.version == s.version and o.subnet_of(s):
                expected = int(t.network_address) + int(o.network_address) - int(s.network_address)
                if expected != int(n.network_address):
                    raise ValueError('CIDR mapping conflicts with asset mapping: ' + source)

def validate_snapshot(data, allow_ranges=False):
    object_value(data, 'snapshot')
    unique_objects(data.get('groups'), 'path', 'groups')
    unique_objects(data.get('services'), 'path', 'services')
    for group in data['groups']:
        booleans(group, ['members_complete'], 'group')
        strings(group.get('members', []), 'members')
        for member in group.get('members', []): networks(member, allow_ranges=allow_ranges)
    for service in data['services']:
        array(service.get('service_entries'), 'service_entries')
    array(data.get('rules'), 'rules')
    if not data['rules']:
        raise ValueError('rules must not be empty')
    for rule in data['rules']:
        object_value(rule, 'rule')
        integer(rule.get('effective_order'), 'effective_order')
        booleans(rule, ['disabled','stateful','sources_excluded','destinations_excluded','logged'], 'rule')
        if rule.get('disabled') is True: continue
        for field in ('source_groups','destination_groups','scope'):
            strings(rule.get(field), field, True)
        strings(rule.get('services', []), 'services')
        if 'profiles' in rule: strings(rule['profiles'], 'profiles')
        array(rule.get('service_entries', []), 'rule.service_entries')

def read_json(path):
    source = pathlib.Path(path)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError('Input exceeds 64 MiB: ' + str(source))
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out: raise ValueError('Duplicate JSON key: ' + key)
            out[key] = value
        return out
    def constant(value): raise ValueError('Non-finite JSON number: ' + value)
    return json.loads(source.read_text(encoding='utf-8'), object_pairs_hook=pairs, parse_constant=constant)
