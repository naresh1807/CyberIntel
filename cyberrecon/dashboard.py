"""Dashboard projections of persisted observations; never expand authorization."""
from collections import Counter
from html import escape
import ipaddress
import json

from .scope import host_of
from .network import clean_url

SECTIONS = (
    ('overview', 'Overview'), ('domains', 'Domains & Subdomains'), ('ips', 'IP Addresses'),
    ('dns', 'DNS Records'), ('ports', 'Ports & Services'), ('nmap', 'Nmap Details'),
    ('technologies', 'Technologies'), ('web', 'Web Information'), ('tls', 'TLS & Certificates'),
    ('findings', 'Security Findings'), ('evidence', 'Evidence & Errors'),
    ('history', 'Scan History'), ('export', 'Export Report'))
VIEW_ALIASES = dict(assets='domains', subdomains='domains', dns='dns', http='web', ports='ports',
                    services='ports', technologies='technologies', urls='web', apis='web',
                    javascript='web', historical='web', findings='findings', relationships='evidence',
                    errors='evidence', hosts='ips')


def normalize_target(value):
    if not isinstance(value, str):
        raise ValueError('Enter a URL, fully qualified domain, or IP address.')
    host = host_of(value)
    return clean_url(value.strip()) if '://' in value else host


def applicable_ports(target, ports):
    try:
        ipaddress.ip_address(host_of(target))
    except ValueError:
        return None
    return ports


def dashboard_rows(snapshot):
    rows = {key: [] for key, _ in SECTIONS if key not in ('overview', 'history', 'export')}
    for kind, section in VIEW_ALIASES.items():
        if kind == 'hosts':
            continue
        for record in snapshot.get(kind, []):
            rows[section].append({'record_type': kind, **record})
    for record in snapshot.get('dns', []):
        if record.get('type') in ('A', 'AAAA'):
            rows['ips'].append({'address': record.get('value'), 'hostname': record.get('host'),
                                'authorization': 'Discovery does not authorize an IP scan', **record})
    for record in snapshot.get('assets', []):
        try:
            ipaddress.ip_address(record.get('host', ''))
        except ValueError:
            continue
        rows['ips'].append(record)
        if 'nmap_host' in record:
            rows['nmap'].append(record)
    rows['nmap'].extend(snapshot.get('services', []))
    for record in snapshot.get('http', []):
        if record.get('tls'):
            rows['tls'].append({'url': record['url'], 'collected_at': record.get('collected_at'),
                                'source': record.get('source'), **record['tls']})
    rows['evidence'].extend({'record_type': 'warning', 'message': warning}
                            for warning in snapshot['scan'].get('warnings', []))
    return rows


def overview_html(snapshot):
    scan = snapshot['scan']
    esc = lambda value: escape(str(value))
    counts = {'Assets': len(snapshot.get('assets', [])),
              'Open ports': sum(p.get('state') == 'open' for p in snapshot.get('ports', [])),
              'Technologies': len(snapshot.get('technologies', [])), 'Findings': len(snapshot.get('findings', []))}
    cards = ' &nbsp; | &nbsp; '.join(f'<b>{number}</b> {label}' for label, number in counts.items())
    severities = Counter(row.get('severity', 'unspecified') for row in snapshot.get('findings', []))
    settings = scan['settings']
    nmap = ('Not selected / domain target requires separately authorized IP scope' if settings.get('ports') is None
            else 'Observed' if snapshot.get('services') else 'No observations; inspect errors (not proof of closed ports)')
    coverage = [('DNS', 'dns'), ('Web / TLS', 'http'), ('Technology detection', 'technologies'),
                ('Passive discovery', 'subdomains'), ('Security observations', 'findings')]
    details = ''.join(f'<li>{label}: {len(snapshot.get(kind, []))} recorded; '
                      f'{"evidence available" if snapshot.get(kind) else "no data / unavailable or not selected"}</li>'
                      for label, kind in coverage)
    return (f'<h1>{esc(scan["target"])}</h1><p>{esc(scan["status"]).upper()} • {esc(scan["started_at"])}</p>'
            f'<h2>{cards}</h2><p>Findings by severity: {esc(dict(severities))}</p>'
            '<p>Confidence, evidence and verification status are separate. Version observations do not confirm vulnerabilities.</p>'
            f'<h3>Coverage</h3><ul>{details}<li>Nmap: {esc(nmap)}</li></ul>'
            '<p>OS detection and intrusive scripts are not part of the default profile. Empty results do not establish safety.</p>'
            f'<h3>Recorded scope</h3><pre>{esc(json.dumps(scan["scope"], indent=2))}</pre>'
            f'<h3>Scan profile</h3><pre>{esc(json.dumps(settings, indent=2))}</pre>'
            f'<h3>Warnings</h3><pre>{esc(chr(10).join(scan.get("warnings", [])) or "None recorded")}</pre>')
