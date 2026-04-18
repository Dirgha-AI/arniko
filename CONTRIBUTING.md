# Contributing to Arniko

Thanks for wanting to help make Arniko better. Arniko is open-source security
tooling — the more eyes on it, the safer it gets.

## Before your first PR

1. **Read the [CLA](CLA.md).** Every contributor signs it. Contributions are
   assigned to Dirgha LLC so we can keep the project coherent and offer
   enterprise support long-term. Standard for a commercial open-source
   security product.

2. **Sign the CLA.** Open your PR with this line in the description:

   > I have read and agree to the Dirgha AI Contributor License Agreement
   > at CLA.md, and I submit this Contribution under those terms.

3. **Read the [LICENSE](LICENSE).** Arniko is Apache-2.0 — free for any
   use, including commercial. Contributions inherit that license.

## Scope — what belongs in Arniko

**Belongs here:**
- New scanner adapters (wrap external CLIs or native libraries)
- New detector heuristics (LLM vulnerabilities, secrets, IaC, supply chain)
- Agent-assisted triage improvements (fix suggestions, severity scoring)
- Output exporters (SARIF, JUnit, SIEM integrations)
- Performance / parallelism improvements
- CI/CD integrations (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- API surface: new endpoints on the Hono server, new dashboard metrics
- Compliance mappings (SOC 2, ISO 27001, PCI-DSS controls → Arniko findings)

**Does not belong here:**
- Closed-source proprietary attack packs (those stay in the commercial
  product — email sales@dirgha.ai if you want to contribute one under
  a different agreement)
- Web front-end chrome / marketing pages
- Billing, licensing, quota enforcement

## Bugs and feature requests

Open a GitHub issue with:
- Expected vs actual behaviour
- Reproduction steps
- Arniko version (`arniko --version`), OS, Node version
- Relevant output with `ARNIKO_DEBUG=1` if it's a runtime issue

**Security vulnerabilities in Arniko itself:** email `security@dirgha.ai`
with details. Do NOT open a public issue for active vulns. We respond within
48 hours.

## Pull requests

- Branch from `main`
- Keep changes focused — one PR per concern
- Run `pnpm test` before pushing — all tests must stay green
- Run `pnpm typecheck` — zero TypeScript errors
- New scanners: include a test that mocks the external CLI and asserts the
  output parser handles success, missing-CLI, and malformed-output cases
- Include a short description of what the change does and why
- Reference the issue number if there is one (`Fixes #123`)

## Code style

- TypeScript strict mode
- No new dependencies without justification in the PR description
- Scanner modules live in `src/scanners/<tool>.ts`, one file per CLI
- Each scanner exports a class extending `BaseScanner`
- Parsers return `ScanResult` with typed findings
- Comments explain **why**, not **what**

## Questions

- Issues: https://github.com/dirghaai/arniko/issues
- Security issues: security@dirgha.ai
- General: team@dirgha.ai

Made with care by Dirgha LLC.
