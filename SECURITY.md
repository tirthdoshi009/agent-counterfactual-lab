# Security

This is an experimental synthetic research harness, not a production security boundary
or a supported enterprise product. Only the current default branch is maintained;
there is no promised security response time or backport policy.

## Report a vulnerability privately

Use the repository's [private vulnerability reporting page](https://github.com/tirthdoshi009/agent-counterfactual-lab/security/advisories/new)
or **Security -> Report a vulnerability**. Do not disclose exploitable details,
credentials or private data in public issues or pull requests. If the private reporting
option is unavailable, do not post details publicly; wait until private reporting is
available.

Provide affected commit/version, expected versus observed behavior and a minimal
synthetic reproduction. Describe the relevant trust boundary and platform. Do not send
real secrets, enterprise content, tenant/account identifiers or raw operational logs.

## Safe investigation

Authorization failures in deliberately vulnerable scripted cases are seeded controls,
not evidence of a live service vulnerability. Report unintended boundary bypasses,
credential exposure, unsafe tool dispatch or incorrect evidence classification.

Use only synthetic fixtures and local capture. Do not probe production systems,
public destinations or unrelated hosts. Fail closed when isolation cannot be proven.
Fake-provider/local transport tests do not establish native isolation or model safety.
A recorded native broker-profile proof covers only its exact source/image/host/profile;
fresh actual proof is required for each live run. Real-model trials remain unverified.
