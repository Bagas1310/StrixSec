# StrixSec

<p align="center">
  <strong>Safe, Modular Security Assessment Toolkit for Authorized Testing</strong>
</p>

<p align="center">
  A Python-based cybersecurity assessment toolkit designed for structured reconnaissance,
  passive security assessment, finding management, and report generation.
</p>

<p align="center">
  <a href="https://github.com/Bagas1310/StrixSec">
    <img src="https://img.shields.io/badge/GitHub-StrixSec-181717?style=flat-square&logo=github" alt="GitHub">
  </a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Tests-162%20passed-success?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License">
</p>

---

## Overview

**StrixSec** is a modular Python security assessment toolkit built for **authorized and non-destructive security testing**.

The project combines:

- Scope management
- DNS and HTTP reconnaissance
- Security header assessment
- Cookie security assessment
- TLS assessment
- Metadata inspection
- Finding generation and storage
- HTML and Markdown reporting
- Security guardrails
- Automated testing
- Docker support
- CI/CD validation

StrixSec is designed around a simple principle:

> **Security assessment should be structured, scoped, observable, and safe by default.**

The toolkit is intended for security learning, defensive engineering, authorized assessments, and controlled testing environments.

---

## ⚠️ Responsible Use

StrixSec is intended **only for systems you own or have explicit permission to assess**.

Do not use this project to:

- Scan systems without authorization
- Circumvent access controls
- Exploit vulnerabilities
- Perform destructive testing
- Conduct unauthorized reconnaissance
- Collect credentials or sensitive information
- Attack third-party infrastructure

The project focuses on **passive and non-destructive assessment techniques**.

Always define and verify your assessment scope before interacting with a target.

See [`SECURITY.md`](SECURITY.md) for the project's security policy.

---

# Features

## Scope Management

StrixSec provides explicit target scope management to prevent accidental assessment of unauthorized assets.

Capabilities include:

- Exact domain validation
- Domain normalization
- IPv4 validation
- CIDR validation
- Scope exclusions
- Redirect scope validation
- Per-target validation
- Per-redirect-hop validation

Example:

```text
Target
  │
  ▼
Scope Normalization
  │
  ▼
Scope Validation
  │
  ├── Allowed ──────► Assessment
  │
  └── Rejected ─────► Stop

  Reconnaissance

The reconnaissance subsystem provides structured, non-destructive information gathering.

DNS
strixsec recon dns <target>

Provides DNS-related reconnaissance information supported by the assessment engine.

HTTP
strixsec recon http <target>

Performs safe HTTP inspection while respecting configured scope.

Technology Detection
strixsec recon tech <target>

Provides technology-related observations supported by the reconnaissance engine.

Security Assessment

StrixSec currently provides several passive assessment modules.

Security Headers

Checks for important HTTP security headers, including:

Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy

Example finding:

Missing Strict-Transport-Security (HSTS) Header
Severity: MEDIUM
Confidence: HIGH
Cookie Security

The assessment engine analyzes cookie-related security attributes and sanitizes sensitive evidence before storage.

Security-related attributes can include:

Secure
HttpOnly
SameSite

Sensitive cookie values are not intended to be exposed through findings or generated reports.

TLS Assessment

StrixSec performs TLS-related inspection as part of its passive assessment workflow.

TLS-related errors are handled as structured assessment results rather than unhandled CLI crashes.

Current limitation: TLS certificate verification is currently disabled in specific reconnaissance paths for compatibility with self-signed certificates. This is documented as an unresolved security issue in the final security review and is planned for future hardening.

See:

docs/final_security_review.md

Metadata Assessment

The metadata assessment module performs controlled HTTP metadata inspection while applying scope validation and response-size limits.

Findings Management

Assessment results are converted into structured findings.

Each finding can contain:

ID
Title
Severity
Category
Asset
Confidence
Status
Description
Evidence
Impact
Remediation
References

Example:

STRX-0001
Missing Strict-Transport-Security (HSTS) Header


Severity     : MEDIUM
Confidence   : HIGH
Status       : OPEN
Category     : SECURITY_HEADER
Asset        : example.com

Findings are stored through the project's database layer and can later be retrieved or included in reports.

Evidence Sanitization

Security findings may contain HTTP evidence that could potentially include sensitive values.

StrixSec implements evidence sanitization before persistence and again during report generation.

Sensitive patterns include:

Authorization:
Cookie:
Set-Cookie:
password=
token=
api_key=
secret=
PEM private keys

Example:

Authorization: Bearer SECRET_TOKEN

becomes:

Authorization: Bearer <REDACTED>

This provides defense-in-depth protection between:

Scanner
   │
   ▼
Evidence
   │
   ▼
Sanitizer
   │
   ▼
Database
   │
   ▼
Report Builder
   │
   ▼
Sanitized Report
Reporting

StrixSec supports structured report generation.

Supported formats include:

HTML
Markdown

Example:

strixsec report generate --format html --output report.html

Generated reports contain structured information such as:

Assessment scope
Assets
Severity summary
Findings
Evidence
Impact
Remediation
References
Methodology

HTML output is escaped to reduce the risk of HTML injection and XSS in generated reports.

CLI

StrixSec provides a command-line interface organized around the main assessment workflow.

Conceptually:

Scope
  │
  ▼
Recon
  │
  ▼
Assess
  │
  ▼
Findings
  │
  ▼
Report
Main Areas
scope       Manage authorized assessment targets
recon       Perform reconnaissance
assess      Run passive security assessments
findings    View stored findings
report      Generate assessment reports

Use:

strixsec --help

to view available commands.

Individual command help is available through:

strixsec <command> --help
Installation
Requirements
Python 3.11+
pip
Git

Clone the repository:

git clone https://github.com/Bagas1310/StrixSec.git
cd StrixSec
Windows

Create a virtual environment:

python -m venv .venv

Activate it:

.\.venv\Scripts\Activate.ps1

Install the project:

pip install -e .

Verify:

strixsec --help
Linux / macOS

Create a virtual environment:

python3 -m venv .venv

Activate it:

source .venv/bin/activate

Install:

pip install -e .

Verify:

strixsec --help
Example Workflow

A typical authorized assessment workflow can look like this:

1. Define Scope

Use a controlled scope configuration.

Example:

examples/sample_scope.json

Only assess assets that are explicitly authorized.

2. Perform Reconnaissance

Example:

strixsec recon dns example.com

Then perform other supported reconnaissance operations.

3. Run Assessment

Example:

strixsec assess all example.com

The assessment engine evaluates the target using passive, non-destructive checks.

4. Review Findings
strixsec findings list

Example:

STRX-0001  Missing HSTS Header
STRX-0002  Missing CSP Header
STRX-0003  Missing X-Content-Type-Options
...
5. Generate Report

HTML:

strixsec report generate --format html --output report.html

Markdown:

strixsec report generate --format markdown --output report.md
Architecture

StrixSec follows a modular architecture.

                         ┌─────────────────┐
                         │      CLI        │
                         └────────┬────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
        ┌─────────┐         ┌──────────┐         ┌──────────┐
        │  Scope  │         │   Recon  │         │ Assess   │
        └────┬────┘         └────┬─────┘         └────┬─────┘
             │                   │                    │
             └───────────────────┼────────────────────┘
                                 ▼
                         ┌──────────────┐
                         │   Findings   │
                         └──────┬───────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
              ┌──────────┐           ┌───────────┐
              │ Storage  │           │ Reporting │
              └──────────┘           └───────────┘
Project Structure
StrixSec/
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── docs/
│   ├── ci-cd.md
│   ├── docker.md
│   ├── final_security_review.md
│   ├── index.md
│   ├── phase7_quality_gates.md
│   ├── phase7_regression_report.md
│   └── phase7_security_audit.md
│
├── examples/
│   └── sample_scope.json
│
├── reports/
│   └── .gitkeep
│
├── strixsec/
│   ├── assessment/
│   ├── cli/
│   ├── core/
│   ├── findings/
│   ├── recon/
│   ├── reporting/
│   ├── safety/
│   ├── scope/
│   ├── storage/
│   └── utils/
│
├── tests/
│   ├── integration/
│   └── unit/
│
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE
├── README.md
├── SECURITY.md
├── docker-compose.yml
└── pyproject.toml
Security Architecture

Security controls are implemented across multiple layers.

                    User Input
                        │
                        ▼
                ┌───────────────┐
                │ Scope Validator│
                └───────┬───────┘
                        │
                        ▼
                ┌───────────────┐
                │ Safety Checks │
                └───────┬───────┘
                        │
                        ▼
                ┌───────────────┐
                │ Recon / Assess│
                └───────┬───────┘
                        │
                        ▼
                ┌───────────────┐
                │   Sanitizer   │
                └───────┬───────┘
                        │
                        ▼
                ┌───────────────┐
                │    Storage    │
                └───────┬───────┘
                        │
                        ▼
                ┌───────────────┐
                │   Reporting   │
                └───────────────┘

Security considerations include:

Scope validation
Redirect scope re-validation
Response size limits
Request timeouts
URL scheme restrictions
Evidence sanitization
SQL parameterization
HTML escaping
CLI error handling
Filesystem safety
Docker non-root execution
CI security checks
Testing

StrixSec includes unit and integration tests.

Current verified test result:

162 passed
0 failed

Quality checks:

pytest -q
ruff check .
ruff format --check .

The latest security review recorded:

Pytest              : 162 passed
Ruff check          : clean
Ruff format         : clean

See:

docs/phase7_quality_gates.md
docs/phase7_regression_report.md
docs/final_security_review.md
Docker

StrixSec includes Docker support.

Build:

docker build -t strixsec .

Run:

docker run --rm strixsec --help

The Docker configuration is designed around:

Python slim base image
Multi-stage build
Non-root runtime user
No unnecessary privileges
No secrets copied into the image
Safe default command

Docker and CI behavior are documented in:

docs/docker.md

CI/CD

The repository includes GitHub Actions workflow validation.

The CI pipeline covers:

Python testing
Code quality checks
Formatting validation
Docker build validation
Smoke testing

CI configuration:

.github/workflows/ci.yml

The project is tested across supported Python versions defined by the CI workflow.

Security Review

A dedicated final security review was performed for the Phase 1–8 implementation.

The review covered:

Scope enforcement
SSRF/network safety
Injection security
Secret/data protection
TLS/HTTP behavior
CLI and filesystem safety
Docker and CI/CD
Dependency/supply-chain considerations
Regression and quality gates

The review identified no critical or high-severity exploitable vulnerabilities, while documenting several defense-in-depth items and one unresolved TLS verification issue for future hardening.

Full review:

docs/final_security_review.md

Security findings documented in the review should be interpreted in the context of the project's authorized, passive, and non-destructive assessment model.

Current Limitations

StrixSec is an evolving security engineering project.

Known limitations include:

TLS verification

Some reconnaissance paths currently use disabled TLS certificate verification to support self-signed certificates.

Planned improvement:

verify=True
      │
      ├── Valid certificate → continue
      │
      └── TLS error → informational finding

with an explicit opt-in mechanism for insecure verification.

Defense-in-depth guardrail wiring

The project contains safety guardrails for sensitive IP ranges, but additional integration into network paths remains planned.

Dependency reproducibility

The project currently does not maintain a dependency lockfile for bit-for-bit reproducible installations.

These limitations are documented rather than hidden because transparent security engineering is a project goal.

Roadmap

Future development may include:

 Stronger TLS verification defaults
 Explicit --insecure opt-in behavior
 Complete network-path safety guardrail wiring
 Improved test isolation
 Dependency lockfile
 Additional security assessment modules
 Expanded report customization
 Improved configuration management
 Additional CI security checks
 More comprehensive documentation
 Release automation
Development

Install development dependencies according to the project's pyproject.toml.

Run tests:

pytest -q

Run linting:

ruff check .

Check formatting:

ruff format --check .

Apply formatting:

ruff format .
Contributing

Contributions are welcome.

Before submitting a pull request:

Keep changes focused.
Add or update tests where appropriate.
Run the test suite.
Run Ruff.
Check formatting.
Review security implications.
Do not include credentials, tokens, private data, or real assessment artifacts.

See CONTRIBUTING.md.

Security Reporting

If you discover a security issue in StrixSec, please follow the responsible disclosure process described in:

SECURITY.md

Please do not publicly disclose sensitive vulnerability details before coordinated review.

License

StrixSec is released under the MIT License.

See LICENSE.

| Area                  | Status         |
| --------------------- | -------------  |
| Core architecture     | ✅ Implemented |
| Scope management      | ✅ Implemented |
| DNS reconnaissance    | ✅ Implemented |
| HTTP reconnaissance   | ✅ Implemented |
| Security assessment   | ✅ Implemented |
| Findings management   | ✅ Implemented |
| HTML reporting        | ✅ Implemented |
| Markdown reporting    | ✅ Implemented |
| Evidence sanitization | ✅ Implemented |
| Automated tests       | ✅ 162 passed  |
| Ruff                  | ✅ Clean       |
| Docker                | ✅ Configured  |
| CI/CD                 | ✅ Configured  |
| Security review       | ✅ Completed   |
| Public release        | ✅ v1.0.0      |

Author

Bagas Ramadhan

GitHub:

https://github.com/Bagas1310

StrixSec is developed as a cybersecurity engineering project focused on:

Secure software design
Defensive security
Security automation
Python development
Security assessment workflows
Testing and quality engineering