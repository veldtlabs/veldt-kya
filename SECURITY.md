# Security Policy

KYA is governance and trust infrastructure for autonomous systems — vulnerabilities here have outsized impact on downstream deployments. We take security reports seriously and respond within one business day.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x  (current) | ✓ |
| < 0.1.0 | ✗ |

We support the latest minor version. Critical security fixes are backported to the previous minor version when feasible.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report privately via one of these channels (in order of preference):

1. **GitHub Security Advisories** — [open a private advisory](https://github.com/veldtlabs/veldt-kya/security/advisories/new) on this repo. Preferred — handles disclosure, CVE assignment, and patch coordination cleanly.
2. **Email** — kola@veldtlabs.ai. PGP key on request.

### What to include

- A description of the vulnerability and the impacted KYA component (e.g., `kya/inbound.py`, `evidence.py`, `delegation_policy.py`)
- Steps to reproduce, including minimal code and KYA version
- The threat model context (what the attacker controls; what they gain)
- A proposed fix or mitigation, if you have one
- Your name and affiliation as you want them credited (or "anonymous")

## Our response timeline

| Stage | Target |
|---|---|
| Acknowledgment of receipt | within **1 business day** |
| Initial triage + severity assessment | within **3 business days** |
| Fix development | within **30 days** for critical/high, **90 days** for medium/low |
| Coordinated public disclosure | within **90 days** of report, or sooner if fix lands earlier |

If the issue is being actively exploited, we'll fast-track disclosure and ship a patch immediately.

## Scope

In scope:
- Authentication / authorization flaws in any KYA component
- Cryptographic weaknesses in the evidence chain (`evidence.py`), the four-gate apply pipeline (`inbound.py`, `_inbound_signing.py`), or the Ed25519-signed federated recommendation flow
- Tenant-isolation bypasses (KYP, principals, weights)
- Composition algebra violations (only-tighten bypass)
- Delegation-attribution evasion in multi-agent fan-out
- Red-team harness escape (`kya_redteam`)
- Supply-chain integrity of the `veldt-kya` PyPI package

Out of scope:
- Issues in third-party agent frameworks (LangChain, CrewAI, etc.) — please report to those projects
- Issues in deployed applications using KYA — please report to those operators
- Findings from automated scanners with no demonstrated exploit
- Social engineering against Veldt Labs personnel

## Safe harbor

We will not pursue legal action against good-faith security researchers who:

- Report vulnerabilities privately and give us reasonable time to respond
- Avoid privacy violations, data destruction, or service disruption during research
- Do not exploit vulnerabilities beyond the minimum necessary to demonstrate impact

## Credit

We publicly credit reporters in the CHANGELOG.md and the GitHub Security Advisory unless they request anonymity.

## Paper-acknowledged limitations

Some KYA primitives have **disclosed structural limitations** documented in the paper (arXiv:2605.25376, §11 Limitations). These are not vulnerabilities; they are intentional design boundaries. Examples:

- Evidence-chain notarization uses HMAC-SHA256 with a single tenant key today. Third-party-attestable notarization (Sigstore / RFC 3161) is on the roadmap.
- External safety filters have a structural ceiling (Nayebi 2025, Proposition 4). KYA composes with — and does not replace — internal model alignment.

Please read §11 of the paper before reporting; it covers what's known.

---

Thank you for helping keep KYA and its downstream users safe.
