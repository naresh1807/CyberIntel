"""Shared canonical DNS facts for native and imported collectors."""
import hashlib
import ipaddress

from .scope import host_of


def dns_attributes(family, value):
    family = family.upper()
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError('Invalid DNS value')
    attributes = {}
    if family in {'A', 'AAAA'}:
        ip = ipaddress.ip_address(value)
        if ip.version != (4 if family == 'A' else 6):
            raise ValueError('Wrong DNS address family')
        value = str(ip)
    elif family == 'MX':
        pieces = value.split()
        if len(pieces) == 2 and pieces[0].isdigit():
            preference = int(pieces[0])
            if not 0 <= preference <= 65535:
                raise ValueError('Invalid MX preference')
            attributes['preference'] = preference
            value = pieces[1]
        value = '.' if value == '.' else host_of(value)
    elif family in {'CNAME', 'NS'}:
        value = host_of(value)
    attributes['value'] = value
    return attributes


def dns_key(host, family, value):
    return host + ':' + family.upper() + ':' + hashlib.sha256(value.encode()).hexdigest()
