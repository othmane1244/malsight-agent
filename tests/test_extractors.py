from malsight.extractors.static import parse_capa_json
from malsight.normalize import iocs_from_strings


def test_parse_cape(case):
    d = case.dynamic
    assert d.source == "cape"
    assert "update.demo.lab" in d.domains
    assert "10.0.0.5" in d.ips
    assert any(c.api == "RegSetValueExW" for c in d.api_calls)


def test_parse_capa_json():
    doc = {"rules": {"persist via Run registry key": {"meta": {
        "namespace": "persistence/registry/run",
        "attack": [{"id": "T1547.001", "technique": "Boot or Logon Autostart Execution"}],
        "mbc": [{"id": "F0012"}]}}}}
    m = parse_capa_json(doc)[0]
    assert m.attack_ids == ["T1547.001"] and m.mbc == ["F0012"]


def test_iocs_from_strings():
    iocs = iocs_from_strings(["contact http://x.demo.lab/a and 192.168.1.10",
                              r"HKCU\Software\Demo"])
    assert "192.168.1.10" in iocs["ip"]
    assert any(u.startswith("http://x.demo.lab") for u in iocs["url"])
    assert "registry_key" in iocs
