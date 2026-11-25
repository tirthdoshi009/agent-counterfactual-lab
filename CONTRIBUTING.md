# Contributing

Use issues for non-sensitive bugs and proposals, and pull requests for focused changes.
Read [SECURITY.md](SECURITY.md) before reporting a possible vulnerability.

Contributions must be your own work or material you are authorized to contribute under
the project's [MIT license](LICENSE). Preserve applicable third-party notices.

Keep fixtures, model payloads and demonstrations synthetic. Do not submit credentials,
private documents, organizational identifiers, operational manifests, raw run evidence
or cloud resources. Do not run against production services or external exfiltration
destinations. Never weaken isolation or treat fake-provider tests as live-model evidence.

After the explicit dependency setup in [README.md](README.md), run:

```sh
uv run --frozen --extra test python -m pytest -q tests
uv run --frozen --extra test ruff check lab tests
```

Add focused behavioral tests for changed mechanics and report what actually ran,
including skipped or unverified platform checks. An isolated native-profile proof is
required before contained live inference; provider credentials/spending require separate
operator approval. Local tests do not establish that proof.

Keep pull requests small, describe the change and its limitations, and do not upload
test outputs containing private operational information.
