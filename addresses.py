"""Exact IP/CIDR/range parsing without silently normalizing CIDR host bits."""
import ipaddress

def networks(value, allow_ranges=False):
    if not isinstance(value,str):raise ValueError('Address must be a string')
    if '-' not in value:return [ipaddress.ip_network(value,strict=True)]
    if not allow_ranges:raise ValueError('Address range requires bounded mode')
    parts=value.split('-')
    if len(parts)!=2:raise ValueError('Malformed address range')
    start,end=map(ipaddress.ip_address,parts)
    if start.version!=end.version or int(start)>int(end):raise ValueError('Invalid address range')
    return list(ipaddress.summarize_address_range(start,end))
