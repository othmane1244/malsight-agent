"""Mise en forme du rapport validé (Markdown) et export des IOC en STIX 2.1."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from malsight.schemas import Report

_TEMPLATES = Path(__file__).parent / "templates"


def to_markdown(report: Report) -> str:
    env = Environment(loader=FileSystemLoader(_TEMPLATES), trim_blocks=True, lstrip_blocks=True)
    return env.get_template("report.md.j2").render(r=report)


def to_stix(report: Report) -> str:
    import stix2
    patterns = {
        "sha256": "[file:hashes.'SHA-256' = '{}']",
        "md5": "[file:hashes.MD5 = '{}']",
        "domain": "[domain-name:value = '{}']",
        "ip": "[ipv4-addr:value = '{}']",
        "url": "[url:value = '{}']",
    }
    indicators = []
    for ioc in report.iocs:
        if ioc.type in patterns:
            value = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
            indicators.append(stix2.Indicator(
                name=f"{ioc.type}: {ioc.value}", pattern_type="stix",
                pattern=patterns[ioc.type].format(value)))
    return stix2.Bundle(objects=indicators, allow_custom=True).serialize(pretty=True)
