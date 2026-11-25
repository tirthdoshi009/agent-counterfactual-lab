import json
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--simulation-output", help="Validate reports from an actual loopback CLI run")
    parser.addoption("--isolation-evidence", help="Validate retrieved native Linux proof evidence")


@pytest.fixture(scope="session")
def simulation_reports(request):
    path = request.config.getoption("--simulation-output")
    if not path:
        pytest.skip("Supply --simulation-output to verify the actual loopback demonstration")
    output = Path(path)
    summary = json.loads((output / "simulation.json").read_text())
    reports = [
        json.loads((output / f"repeat-{index + 1}" / "report.json").read_text())
        for index in range(summary["repeats"])
    ]
    return summary, reports


@pytest.fixture(scope="session")
def isolation_evidence(request):
    path = request.config.getoption("--isolation-evidence")
    if not path:
        pytest.skip("Supply --isolation-evidence for actual native Linux proof validation")
    directory = Path(path)
    return directory, json.loads(
        (directory / "abl-proof-4" / "isolation-proof.json").read_text()
    )

