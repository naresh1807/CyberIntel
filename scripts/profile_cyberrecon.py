#!/usr/bin/env python3
"""Bounded local persistence/export profile; no DNS/network/external tools."""
import cProfile
import json
import pstats
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cyberrecon.reporting import export_reports
from cyberrecon.storage import Repository


def main():
    timings = {}
    with tempfile.TemporaryDirectory(prefix='cyberrecon-profile-') as temporary:
        repo = Repository(Path(temporary) / 'workspace')
        project = repo.create_project('Synthetic profile', ['example.org'], authority='Offline synthetic profile')
        identifier = repo.start_scan(project, 'example.org', {})
        start = time.perf_counter()
        for index in range(1000):
            url = f'https://example.org/path/{index}'
            repo.save(identifier, 'urls', url, {'url':url, 'verified':False}, 'offline synthetic')
            if index < 150:
                repo.save(identifier, 'relationships', str(index), {'from_node':'host:example.org', 'to_node':'url:'+url, 'relation':'serves'}, 'offline synthetic')
        timings['persist_1150_records_seconds'] = round(time.perf_counter()-start, 3)
        start = time.perf_counter(); repo.finish(identifier, [])
        timings['finish_json_seconds'] = round(time.perf_counter()-start, 3)
        start = time.perf_counter(); repo.snapshot(identifier)
        timings['snapshot_seconds'] = round(time.perf_counter()-start, 3)
        start = time.perf_counter(); export_reports(repo, identifier, Path(temporary) / 'reports')
        timings['all_reports_seconds'] = round(time.perf_counter()-start, 3)
    print(json.dumps(timings, indent=2))


if __name__ == '__main__':
    profile = cProfile.Profile()
    profile.runcall(main)
    pstats.Stats(profile).strip_dirs().sort_stats('cumulative').print_stats(12)
