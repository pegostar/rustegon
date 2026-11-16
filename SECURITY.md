# Security Policy

## Supported versions
Rustegon is pre-1.0 and under active development. Only the `main` branch receives security
fixes; there are no supported releases yet. The support window for releases will be defined
before 1.0.

## Reporting a vulnerability
**Do not open a public issue for security problems.**

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" in the repository's Security tab). Please include:
- affected component and version or commit,
- impact (data exposure, privilege escalation, durability or isolation violation, denial of
  service, …),
- reproduction steps or a proof of concept,
- whether the issue is already public.

We will acknowledge the report, agree on a disclosure timeline with you, and credit you in the
advisory unless you prefer otherwise.

## Scope
In scope: the server (`rustegond`), CLI, drivers, GUI, packaging and the documented security
guarantees (`docs/architecture/security.md`). Violations of durability or isolation guarantees
(`docs/architecture/transaction-management.md`, `consistency.md`) are treated as security issues.

## Security defaults
Rustegon ships secure by default: TLS on (rustls, no OpenSSL), no default credentials, SCRAM
authentication, secrets referenced by file or provider and never logged (`Redacted<T>`),
encryption at rest proposed by the init wizard. Dependencies are checked by `cargo deny` and
`cargo audit` in CI.
