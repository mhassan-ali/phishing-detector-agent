# Security Policy

## Supported versions
Only the latest release receives security fixes.

## Reporting a vulnerability
Please **do not open a public issue**. Report privately via GitHub Security Advisories on this repository, or email
_<security contact: add before release>_. Include steps to reproduce, impact, and affected version.
Expect an acknowledgement within 7 days.

## Scope examples
SSRF bypass, prompt-injection that flips a verdict, auth bypass, secret leakage, unsafe attachment handling,
dependency vulnerabilities.

## Out of scope
Missed detections of individual phishing samples (please open a regular issue with a *synthetic* reproduction),
social engineering of maintainers, denial of service via unlimited traffic against self-hosted instances.

## Safe harbor
Good-faith research following this policy will not be pursued.

## Hardening references
See `docs/04-threat-model.md` and `docs/08-deployment-guide.md`.
