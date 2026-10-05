import shutil
import struct
import subprocess

import pytest

from cyberintel.analysis import analyze_pcap


def write_dns_capture(path):
    dns = struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53535, 53, 8 + len(dns), 0) + dns
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x35") + udp
    packet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip
    path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1790816400, 0, len(packet), len(packet)) + packet)


def test_tshark_adapter_with_simulated_process(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.pcap"
    write_dns_capture(path)
    monkeypatch.setattr("shutil.which", lambda _: "tshark")
    def run(command, stdout, stderr, **kwargs):
        assert "-r" in command and "-n" in command and "-i" not in command
        assert kwargs["timeout"] == 120
        stdout.write(b'"1","1790816400","71","DNS","192.0.2.1","","192.0.2.53","","","53535","","53","example.com","",""\n')
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr("subprocess.run", run)
    result = analyze_pcap(path, data_kind="synthetic")
    assert result.data["packets"] == 1
    assert result.data["dns_queries"][0]["query"] == "example.com"
    assert result.status == "synthetic"


@pytest.mark.skipif(not shutil.which("tshark"), reason="TShark is not installed")
def test_real_tshark_synthetic_capture(tmp_path):
    path = tmp_path / "synthetic.pcap"
    write_dns_capture(path)
    result = analyze_pcap(path, data_kind="synthetic")
    assert result.data["packets"] == 1
    assert result.data["dns_queries"][0]["query"] == "example.com"
