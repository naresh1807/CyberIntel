"""Lab diagnostics preserve bounded failures and unchanged production defaults."""
import sys
from pathlib import Path

import pytest

from cyberrecon.engines import ToolError, port_scan, run_process
from cyberrecon.scope import Scope


def test_diagnostics_capture_failure_without_hiding_it():
    records = []
    with pytest.raises(ToolError, match='tool_failed'):
        run_process([sys.executable, '-c', 'import sys; print("owned fixture"); sys.stderr.write("fixture failure"); sys.exit(7)'], diagnostic=records.append)
    assert records[0]['returncode'] == 7
    assert records[0]['stdout'] == 'owned fixture\n'
    assert records[0]['stderr'] == 'fixture failure'


@pytest.mark.parametrize('unprivileged', [False, True])
def test_lab_mode_is_explicit_tcp_only(monkeypatch, unprivileged):
    commands = []
    def execute(args, **kwargs):
        commands.append(args)
        Path(args[args.index('-oX') + 1]).write_bytes(b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>')
    monkeypatch.setattr('cyberrecon.engines.run_process', execute)
    scope = Scope(['127.0.0.1'])
    result, _ = port_scan('127.0.0.1', scope, '443', unprivileged=unprivileged)
    assert result['records'][0]['state'] == 'open'
    assert ('--unprivileged' in commands[0]) == unprivileged
    assert '-sT' in commands[0] and '-Pn' in commands[0] and '-sU' not in commands[0]
    with pytest.raises(ValueError):
        port_scan('127.0.0.1', scope, '443', udp=True, unprivileged=True)
    assert len(commands) == 1
