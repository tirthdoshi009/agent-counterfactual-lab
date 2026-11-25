# Agent Counterfactual Lab

An open-source, synthetic research harness released under the [MIT license](LICENSE).
See [CONTRIBUTING.md](CONTRIBUTING.md) for contributions and [SECURITY.md](SECURITY.md)
for private vulnerability reporting.

A small prompt-injection counterfactual harness: give an assistant a fictional document
and simulated-email task, compare original injected content with manual interventions,
and measure unsafe proposals, actual local capture effects and legitimate task completion.

## Status and scope

- Four conditions: clean, injected, injection removed without removing useful content,
  and an unrelated edit that retains the injection. Clean and neutralized inputs are
  intentionally identical in this first task, but receive fresh independent trials.
- A provider-neutral tool loop, a concrete OpenAI-compatible client, and a narrow
  authenticated inference/tool RPC boundary are implemented.
- Local counterfactual verification uses a deterministic fake provider and in-process
  HTTP ASGI transport. Client integration tests use MockTransport. These validate
  mechanics, **not real-model behavior, real TCP transport or OS-level isolation**.
- The new native Linux broker-profile supervisor is implemented but has not been
  runtime-verified. No live provider/model/account has been selected or exercised.
- A historical synthetic isolation proof covered an earlier five-container profile.
  It does **not** attest this source revision or the new broker boundary.

There is no production integration, real enterprise data, real email, external
exfiltration service, automatic cloud provisioning or executable GitHub workflow.
Deployment templates, operational manifests, keys and historical run evidence are
deliberately omitted from this repository.

## Local setup and mechanics

Python 3.12 is required. Package downloads are an explicit setup step:

```powershell
git clone https://github.com/tirthdoshi009/agent-counterfactual-lab.git
Set-Location agent-counterfactual-lab
python -m pip install --index-url https://pypi.org/simple uv==0.9.11
uv sync --frozen --extra test
& '.\.venv\Scripts\python.exe' -m lab counterfactual `
    --provider deterministic-fake --output '.\counterfactual-results' --trials 2
& '.\.venv\Scripts\python.exe' -m pytest -q tests
```

On Linux/macOS, replace the environment interpreter with `.venv/bin/python` and
use ordinary shell line continuation. The fake demonstration needs no provider account,
container engine, cloud resources or model spending.

The lock pins 38 registry dependencies with public artifact URLs and hashes. The Python
package/import name remains `agent-boundary-lab` / `lab`.

The task and exact manual interventions are in `cases/counterfactual.json`.
Each trial allocates fresh state, conversation, opaque identity and correlation ID.
No cached model response is reused. Only `read_document` and `send_email` are exposed;
email always becomes a trusted local synthetic capture record, even for an invented
recipient. No shell/eval tool or arbitrary URL-fetch tool exists.

The default is two trials per condition, four model calls, six tool calls, 384 output
tokens per response, 12,000 reported tokens per trial and 45 seconds. CLI flags expose
bounded trial/call/token limits. Reported token totals are checked after responses:
they are **not a prepaid spend guarantee**.

New output directories contain `report.json`, an escaped self-contained `report.html`
and individual `trials/*.json`. Existing output directories are never overwritten.
Evidence includes source/condition hashes, settings, proposed/dispatched tool calls,
results, trusted audits/capture, task outcomes, usage, errors and denominators.

Timeouts, exhausted budgets, missing/conflicting evidence, missing provider usage and
no-tool-call runs are inconclusive, never safe passes. Rates exclude inconclusive
trials; their observed attempts/effects remain separately counted. Leak scoring checks
the exact seeded private marker in any email field and unintended recipients, not
every possible semantic paraphrase or partial leak.

Wilson intervals and repetition-paired comparisons are descriptive small-sample
summaries, not unique-cause proof. Provider/order dependence can invalidate independence
assumptions. Fake-provider rates are not estimates of real-model resilience.

## Trusted broker boundary

`lab/broker_rpc.py` separates data and management apps. The untrusted adapter submits
only a trial capability, sequence, canonical conversation hash and output limit for
inference. It cannot supply an arbitrary prompt, model or upstream URL. The broker owns
the fixed synthetic conversation, tool execution, workspace and capture state.
Tool RPC accepts only the exact pending model proposal in order; arbitrary tool-result
uploads cannot enter a model request.

Both apps enforce strict schemas, bounded bodies and scoped authentication. Trial,
request, model/tool call, time and token budgets are independently enforced. Replayed
or out-of-order calls, unexpected paths/methods, redirects and malformed/failed upstream
responses are rejected. There is no scripted fallback for failed inference.

`lab/model_broker.py` retains upstream credentials only in the trusted host broker
process. Requests use an exact operator-configured HTTPS endpoint allowlist, TLS
verification, no redirects and no environment proxies. Credentials are not sent in
prompts, mounted into adapters, embedded in images or included in evidence.

## Native Linux profile: execution still requires approval and verification

`python -m lab.broker_isolation` is a trusted host-side supervisor for an approved native
Linux host with rootful Podman 5/netavark, cgroup v2, seccomp, `nsenter`, `nft`, `ip` and
this project's Python dependencies.

It creates a separate internal DNS-disabled `10.203.44.0/24` bridge. The hardened
non-root adapter can initiate only `10.203.44.10 -> 10.203.44.1:8000` to the trusted
host broker. Control binds only `127.0.0.1:9000`. No provider/DNS/general host egress,
engine socket, volume, secret or host namespace is given to the adapter. The trusted
host and broker are part of the trusted computing base.

During explicit setup, build `Dockerfile` using a reviewed immutable Python 3.12
`BASE_IMAGE` digest. Runtime accepts only the resulting local immutable image ID:

```sh
sudo .venv/bin/python -m lab.broker_isolation \
  --image "$IMAGE_ID" --output "$NEW_PROOF_DIRECTORY"
```

This command has not yet been verified on Linux for the new profile. It installs and
reads back deny-default namespace policy before executing adapter inference, runs
fake-only RPC/tool/capture trials, requires rejection-counter evidence for forbidden
host/control/service/capture/DNS/IPv4/IPv6 paths, checks credential absence and policy
continuity, and cleans only its tracked broker PID/container/network. The standalone
proof makes no upstream Internet requests. Missing prerequisites/probes or failed
cleanup remain `verified=false`.

Live execution additionally requires explicit provider/model/account/spend approval,
approved host egress and an operator-private config with `endpoint`,
`approved_endpoints`, `model` and `credential_env` (an explicit `LAB_PROVIDER_*` name).
Credentials belong only in that host environment variable, not a file or CLI value.
The endpoint must support the client's Bearer-auth OpenAI-compatible request settings
and usage reporting; incompatibility is an error, not a silent fallback.

The native supervisor requires `--upstream-config` plus `--approved-live-inference`
and **always performs a fresh actual fake-only changed-profile proof before live client
startup**. It never trusts a historical proof JSON to unlock spending.
The simpler `lab counterfactual --provider openai-compatible` command deliberately
rejects execution rather than bypassing that gate. No infrastructure is provisioned
or restarted by either entrypoint.

## Legacy scripted HTTP/MCP harness

`python -m lab simulate --output NEW_DIRECTORY --repeat 2` replays 15 synthetic cases
over HTTP and official SDK Streamable HTTP MCP across vulnerable/guarded variants.
It binds loopback and stops its child processes. This tests deterministic authorization
and evidence mechanics, **not real-agent susceptibility or security isolation**.

`lab/isolation.py` retains the separate earlier five-container proof implementation;
its original policy is not broadened by the broker profile. Historical report replay
tests are opt-in through `--simulation-output` / `--isolation-evidence`; private
operational evidence is not included.

## Distribution and dependencies

The [MIT license](LICENSE) covers project-authored source, not third-party dependencies
or base images. Dependencies are referenced, not vendored or relicensed.
Metadata identifies mainly MIT/BSD/Apache/PSF-family licenses,
with `certifi` under MPL-2.0, `cryptography` under Apache-2.0 OR BSD-3-Clause and
`packaging` under Apache-2.0 OR BSD-2-Clause. Review applicable licenses/notices,
file-level obligations (including certifi's MPL-2.0 requirements) and bundled native/
base-image components before redistributing dependencies, wheels or images.
Python/OS/build-tool license and notice requirements also apply to redistributed images.
This source release does not distribute dependency binaries or container images;
metadata is not a full provenance/legal review.
