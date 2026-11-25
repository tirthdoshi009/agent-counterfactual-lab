from datetime import UTC, datetime
from html import escape
import importlib.metadata
import json
import os
from pathlib import Path
import platform

from lab.contracts import ROOT, digest
from lab.evaluator import summarize


def normalized(executions: list[dict]) -> list[dict]:
    """Stable decisions/scores; raw evidence retains correlation identifiers."""
    return [{
        "case_id": e["case_id"], "variant": e["variant"], "transport": e["transport"],
        "proposal_hash": e.get("proposal_hash"),
        "decisions": [(t["reply"]["decision"], t["reply"]["reason"], t["reply"]["data"])
                      for t in e.get("transcript", [])],
        "evaluation": e["evaluation"],
    } for e in executions]


def manifest(suite: dict, fixture: dict, isolation: dict) -> dict:
    packages = {dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()}
    lock = ROOT / "uv.lock"
    image_identity = ROOT / "image-identity.json"
    return {
        "created_at": datetime.now(UTC).isoformat(),
        "suite_version": suite["version"], "suite_hash": digest(suite),
        "fixture_hash": digest(fixture),
        "source_hash": digest({
            str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "lab").rglob("*.py"))
        }),
        "lock_hash": digest(lock.read_text(encoding="utf-8")) if lock.exists() else None,
        "python": platform.python_version(), "dependencies": dict(sorted(packages.items())),
        "image": json.loads(image_identity.read_text()) if image_identity.exists() else {
            "status": "not_container_validated",
            "declared": os.environ.get("LAB_IMAGE", "agent-boundary-lab:0.1.0"),
        },
        "isolation": isolation,
        "limits": {key: suite[key] for key in (
            "max_calls", "case_timeout_seconds", "call_timeout_seconds"
        )},
        "identities": fixture["principals"],
        "disclaimer": "Scripted harness validation, not LLM resilience or Agent365 controls.",
    }


def write_reports(output: Path, metadata: dict, executions: list[dict]) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "manifest": metadata, "summary": summarize(executions),
        "normalized_hash": digest(normalized(executions)), "executions": executions,
    }
    encoded = json.dumps(report, indent=2, ensure_ascii=True)
    (output / "report.json").write_text(encoded + "\n", encoding="utf-8")
    rows = "".join(
        "<tr>" + "".join(f"<td>{escape(str(row[key]))}</td>" for key in (
            "variant", "transport", "valid_adversarial", "attack_successes",
            "valid_benign", "benign_successes", "inconclusive", "attempted_but_blocked",
        )) + "</tr>" for row in report["summary"]
    )
    details = "".join(
        f"<details><summary>{escape(e['case_id'])} / {escape(e['variant'])} / "
        f"{escape(e['transport'])}: {escape(e['evaluation']['attempt'])}</summary>"
        f"<pre>{escape(json.dumps(e, indent=2, ensure_ascii=True))}</pre></details>"
        for e in executions
    )
    html = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'"><title>Agent Boundary Lab</title>'
        "<style>body{font:16px system-ui;margin:2rem;max-width:1100px}"
        "table{border-collapse:collapse}td,th{border:1px solid #888;padding:.5rem}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin:1rem 0}</style>"
        "<h1>Agent Boundary Lab</h1>"
        "<p>Synthetic scripted harness validation. Not real-model resilience or Agent365 controls.</p>"
        "<p>Attack rates exclude inconclusive executions. Benign success is reported separately.</p>"
        "<table><thead><tr><th>Variant</th><th>Transport</th><th>Valid attacks</th>"
        "<th>Successful attacks</th><th>Valid benign</th><th>Successful benign</th>"
        f"<th>Inconclusive</th><th>Blocked attempts</th></tr></thead><tbody>{rows}</tbody></table>"
        f"<h2>Manifest</h2><pre>{escape(json.dumps(metadata, indent=2))}</pre>"
        f"<h2>Correlated evidence</h2>{details}</html>"
    )
    (output / "report.html").write_text(html, encoding="utf-8")
    return report

