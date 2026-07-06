# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| v0.16.x (latest release) | Yes |
| v0.15.x | No |
| older releases | No |

Always update to the latest release: `innerwarden upgrade`

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Use [GitHub private vulnerability reporting](https://github.com/InnerWarden/innerwarden/security/advisories/new) to report securely.

Include:

- InnerWarden version (`innerwarden status`)
- Steps to reproduce
- Impact (what an attacker can do)
- Whether responder was enabled (`dry_run = true` or `false`)

## What We Do — SLA

| Stage | Target | Notes |
| --- | --- | --- |
| Acknowledgement | **48 hours** | A human reads your report and confirms receipt. |
| Initial triage | **30 days** | Severity assigned, owner named, tentative fix timeline shared. |
| Fix for Critical / High | **90 days** | Patched release published. Active in-the-wild exploitation triggers the IR runbook (hours-not-days response). |
| Fix for Medium | **120 days** | Patch or documented mitigation. |
| Fix for Low | next release cycle | Bundled into normal cadence. |
| Public disclosure | within 14 days of fix | Joint advisory via GHSA; CVE where applicable; reporter credited unless they prefer anonymity. |

Inner Warden is solo-maintained today. The commitments above are the policy we hold ourselves to. If we cannot hit a milestone we tell you why and propose a new date — silence is not an acceptable response from us.

For the full disclosure policy (severity definitions, scope, safe-harbour language, what we ask of reporters), see the [**Vulnerability Disclosure Policy**](https://github.com/InnerWarden/innerwarden/wiki/Vulnerability-Disclosure-Policy) on the wiki.

For project-level incident response (what happens if our signing key, CI, or release pipeline is compromised), see the [**Incident Response Runbook**](https://github.com/InnerWarden/innerwarden/wiki/Incident-Response).

## Supply Chain

Detailed in [docs/supply-chain-security.md](docs/supply-chain-security.md): release flow, embedded Ed25519 release-key fingerprint, manual verification recipe (`SHA-256` + `.sig` + `gh attestation verify`), and an honest list of current limits (no `.deb`/`.rpm` yet, no SBOM yet, no hardware-backed signing yet).

The short version:

- Stable releases ship per-binary `.sha256` and `.sig` (Ed25519). The installer (`install.sh`) and the updater (`innerwarden upgrade`) fail-closed when signatures are missing or invalid (Spec 048).
- The 6 release **binaries** (sensor + agent + ctl × x86_64/aarch64) carry a [GitHub Artifact Attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) (SLSA v1 provenance) verifiable via `gh attestation verify`. The sidecar files (`.sha256`, `.sig`, `SHA256SUMS`, `install.sh`) are not currently attested individually.
- Stable tags publish an aggregate `SHA256SUMS` + `SHA256SUMS.sig` (GPG) for the manual-verification path. Prerelease/canary tags publish `SHA256SUMS` only; the GPG signature is gated to stable.
- Active Ed25519 key fingerprint (SHA-256 of the release public key): `9cba21f2d6a45e7f58edd9b840e152b5c7d0ee6e511bb6835037088c6a89143f`, pinned in `docs/supply-chain-security.md`. The raw key material is in `crates/ctl/src/upgrade.rs::RELEASE_PUBLIC_KEY_B64` and `install.sh::INNERWARDEN_RELEASE_PEM`.

## Security Features

Inner Warden includes:

- **Dependency auditing** - cargo-deny runs on every push (RustSec advisories + license compliance)
- **Secrets scanning** - gitleaks + GitHub secret scanning with push protection
- **Automated dependency updates** - Dependabot weekly
- **GitHub Actions pinned to SHA** - prevents supply chain attacks
- **Branch protection** - CI + Security checks required before merge
- **Release signing** - Ed25519 per-binary signatures + SHA-256 sidecars + GitHub Artifact Attestations; install/upgrade paths fail-closed on missing/invalid signatures for stable releases (Spec 048)
- **Append-only audit trail** - every decision logged to JSONL, immutable
- **Safe defaults** - dry_run = true, responder disabled, confidence threshold above max on install
