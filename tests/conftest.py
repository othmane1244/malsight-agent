import json
from pathlib import Path

import pytest

from malsight.extractors.dynamic import parse_cape
from malsight.schemas import Case, CapaMatch, SampleInfo

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def case() -> Case:
    dyn = parse_cape(json.loads((FIX / "cape_mini.json").read_text()))
    return Case(
        sample=SampleInfo(filename="demo.exe", sha256="a" * 64, md5="b" * 32, size=1024, file_type="PE"),
        imports={"advapi32.dll": ["RegSetValueExW"], "kernel32.dll": ["CreateProcessW", "Sleep"]},
        strings=["http://update.demo.lab/check", "DemoApp"],
        capa=[CapaMatch(rule="persist via Run registry key", attack_ids=["T1547.001"])],
        dynamic=dyn,
    )


class FakeKB:
    known = {"T1547.001": "Registry Run Keys / Startup Folder", "T1059.003": "Windows Command Shell"}

    def is_valid(self, tid): return tid in self.known
    def name(self, tid): return self.known.get(tid, "")
    def tactic(self, tid): return "persistence" if tid == "T1547.001" else "execution"
    def search(self, q, k=5): return list(self.known.items())[:k]


@pytest.fixture
def kb():
    return FakeKB()
