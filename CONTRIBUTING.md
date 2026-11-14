# Contributing to PhishGuard

Thanks for helping! This is a defensive security project; please read `AGENTS.md` and `docs/09-privacy-and-ethics.md` first.

## Setup
```bash
uv sync && uv run pre-commit install
```

## Workflow
1. Open an issue describing the change; link requirement IDs (`FR-*`, `NFR-*`).
2. Branch: `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`.
3. Keep changes small; add tests (unit + adversarial where relevant).
4. Run: `ruff check . && ruff format --check . && mypy src && pytest --cov && bandit -r src`.
5. Update docs and `CHANGELOG.md`; add an ADR for significant decisions.
6. Open a PR using the checklist below.

## Commit style
Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `security:`.

## PR checklist
- [ ] Tests added/updated; coverage not reduced
- [ ] Lint, type-check, security scans pass
- [ ] Docs and CHANGELOG updated
- [ ] No secrets, no real phishing samples, no real-network tests
- [ ] Threat model reviewed if a trust boundary changed

## Rules for samples and fixtures
Use synthetic content only (`example.com`, `.test`, `.invalid`). Never commit live phishing kits or real victim data.

## Code of conduct
Be respectful and constructive. Harassment or offensive-use requests will be declined.
