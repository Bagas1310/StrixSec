# Security Policy & Responsible Disclosure

## Safety & Legal Notice

StrixSec is designed strictly for **authorized security assessments, penetration testing, and defensive research**. Users must ensure they have explicit written permission before assessing any system or network infrastructure.

---

## Safety Guardrails

StrixSec includes built-in safety guardrails in `strixsec/safety/guardrails.py` to prevent accidental scanning of out-of-scope targets, restricted IP ranges (e.g. localhost, cloud metadata endpoints, broadcast addresses), or unapproved target domains.

---

## Reporting Vulnerabilities

If you discover a security vulnerability within StrixSec itself:

1. **Do NOT open a public GitHub issue.**
2. Send a detailed report describing the vulnerability, proof-of-concept, and impact to `security@strixsec.local`.
3. We will acknowledge receipt of your vulnerability report within 48 hours and provide regular updates on remediation progress.
