from cyberrecon.intelligence import assess, identify


def test_exact_cycles_and_no_cve_claim():
    payload = {"result": {"name": "nginx", "releases": [{"name": "1.2", "isEol": True},
                {"name": "1.24", "isEol": False}]}}
    assert assess("nginx", "1.24.3", payload)["status"] == "NOT_EOL"
    assert assess("nginx", "1.2.4", payload)["status"] == "EOL"
    assert assess("nginx", "1.25.0", payload)["status"] == "UNKNOWN"
    assert assess("nginx", "hidden", payload)["status"] == "UNKNOWN"
    assert assess("nginx", "1.2.4", {"result": {"name": "other"}})["status"] == "UNKNOWN"


def test_identification():
    assert identify({"banner": "nginx/1.24.3"}) == ("nginx", "1.24.3")
    assert identify({"banner": "nginx"}) == (None, "")
