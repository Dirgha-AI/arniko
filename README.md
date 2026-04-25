# Arniko

**AI security scanner. Every tool, one unified report.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](./LICENSE)
[![Tests: 56/56](https://img.shields.io/badge/tests-56%2F56%20passing-success?style=flat-square)](./tests)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%99%A1-ec4899?style=flat-square)](https://dirgha.ai/contribute)

---

Arniko is a security scanner for AI-era stacks. Run one command and it fans out across **36 best-in-class tools** — gitleaks, semgrep, trivy, bandit, checkov, snyk, grype, falco, deepteam, garak, llm-guard, purple llama, rebuff, promptfoo, and 22 others — covering LLMs, code, containers, infrastructure, and supply chain. Findings come back as one normalized stream; agents triage, rank, and propose fixes.

One dashboard. One SARIF export. Open-source. Part of the [Dirgha AI OS](https://github.com/Dirgha-AI/Rama-I-Dirgha-AI-OS).

## What it scans

| Domain | Scanners | Looks for |
|---|---|---|
| **LLM** | DeepTeam, Garak, Promptfoo, LlmGuard, NeMo Guardrails, Rebuff, Purple Llama, OWASP-LLM-Top-10, indirect-injection, prompt-injection, agentic-security | Jailbreaks, prompt injection, data exfiltration, PII leakage, indirect-prompt attacks, tool-call abuse |
| **Code** | Semgrep, Bandit, CodeQL, Snyk-Code | SAST — dangerous patterns, CWE coverage |
| **Secrets** | Gitleaks, Trufflehog | API keys, tokens, credentials committed to git |
| **Containers** | Trivy, Grype, Falco | CVEs in images, runtime misconfigurations |
| **Infrastructure** | Checkov | IaC misconfigurations (Terraform, K8s, CloudFormation) |
| **Supply chain** | OWASP Dependency-Check, Socket, Snyk-OSS, SLSA-provenance, Tool-Attestation, Model-Provenance | Vulnerable deps, malicious packages, build-chain attacks, SBOM validation |

## Install

```bash
pnpm install @dirgha/arniko      # or: npm install -g @dirgha/arniko
```

Requires Node 20+. External scanner CLIs (gitleaks, trivy, semgrep, bandit,
etc.) are **optional** — Arniko auto-detects what's installed and skips
the rest. Each adapter fails gracefully.

## Quick start

```bash
# Start the API server
arniko start

# Or programmatically
import { ArnikoOrchestrator } from '@dirgha/arniko';

const orchestrator = new ArnikoOrchestrator({ db: { connectionString: '…' } });
const result = await orchestrator.scan({
  targetType: 'repo',
  targetId: '/path/to/repo',
  tools: ['gitleaks', 'semgrep', 'trivy'],
});

console.log(result.findings);
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       HTTP API (Hono)                        │
│   /api/scans  ·  /api/dashboard  ·  /api/health  · /api/sif  │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│                      ArnikoOrchestrator                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  queue   │→ │ scanners │→ │detectors │→ │  agents      │  │
│  │ parallel │  │ 36 tools │  │ ML + rule│  │ triage / fix │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
│                       │           │            │             │
│                       └───────────▼────────────┘             │
│                                findings                      │
│                                   │                          │
│                  ┌────────────────┴──────────────┐           │
│                  ▼                               ▼           │
│           ┌──────────────┐                ┌────────────┐     │
│           │  postgres    │                │ exporters  │     │
│           │  (drizzle)   │                │ SARIF ·    │     │
│           │  scans +     │                │ JUnit ·    │     │
│           │  findings +  │                │ JSON ·     │     │
│           │  trends      │                │ SIEM       │     │
│           └──────────────┘                └────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

## Source tree

```
src/
├── orchestrator.ts        # Scan queue, parallel execution, dedup
├── server.ts              # Hono HTTP server
├── cli.ts                 # CLI entry point
├── index.ts               # Public API
│
├── scanners/              # 36 scanner adapters (one file per tool)
│   ├── baseScanner.ts     # Abstract base + CLI-detection helper
│   ├── llm/               # LLM-oriented scanners
│   ├── code/              # SAST scanners
│   ├── secrets/           # Secret detection
│   ├── containers/        # Image + runtime
│   ├── infra/             # IaC
│   └── supply-chain/      # SBOM + provenance
│
├── detectors/             # Higher-level heuristics
│   ├── mlDetector.ts      # ML model that scores findings
│   ├── riskCalculator.ts  # CVSS-aware scoring
│   ├── ruleEngine.ts      # Rule DSL for custom detections
│   └── supplyChainGuard.ts
│
├── agents/                # AI-assisted triage
│   ├── fixAgent.ts        # Proposes fixes
│   └── triageAgent.ts     # Ranks and groups findings
│
├── api/                   # HTTP routes
│   ├── routes.ts          # /api/scans, /api/findings
│   ├── dashboard.ts       # /api/dashboard/*
│   └── dashboard-real.ts  # Live metrics
│
├── db/                    # Drizzle ORM, Postgres
├── compliance/            # SOC 2, ISO 27001, PCI-DSS mappings
├── dashboard/             # Dashboard data layer
├── exporters/             # SARIF, JUnit, JSON, SIEM formats
├── monitors/              # Real-time scan monitors
├── performance/           # Parallel executor, rate limiting
├── security/              # Arniko's own hardening (auth, CSRF, SAST)
├── middleware/            # Auth, rate-limit, logging
├── ci/                    # GitHub Actions + GitLab CI integrations
├── integrations/          # Alerts (email, Slack), SIEM push
├── services/              # LLM scan service, Lightning billing
└── types/                 # Shared types
```

**Totals:** 72 TypeScript files, ~18,000 lines, 56 passing tests.

## API

### Start a scan

```http
POST /api/scans
Authorization: Bearer <ARNIKO_API_KEY>
Content-Type: application/json

{
  "targetType": "repo",
  "targetId": "/path/to/repo",
  "tools": ["gitleaks", "semgrep", "trivy"],
  "config": { "severity": ["high", "critical"] }
}
```

Returns `{ scanId, status: "queued" }`. Scan runs async.

### Get scan status

```http
GET /api/scans/:id
```

Returns scan state, findings, metrics.

### Dashboard

```http
GET /api/dashboard/summary     # Current counts by severity
GET /api/dashboard/trends      # Historical trend data
GET /api/dashboard/top-risks   # Highest-scoring open findings
```

### Health

```http
GET /api/health
```

Returns scanner availability, DB health, queue depth.

## Configuration

```bash
# Required
DATABASE_URL=postgres://user:pass@host:5432/arniko

# Auth
ARNIKO_API_KEYS=key1,key2,key3     # Comma-separated allowlist

# Optional integrations
RESEND_API_KEY=…                   # Email alerts via Resend
GITHUB_TOKEN=…                     # GitHub Actions integration

# Lightning (experimental billing)
LND_TLS_CERT=…
LND_MACAROON=…
LND_HOST=…

# Runtime
PORT=3010                          # Default 3010
ARNIKO_DEBUG=1                     # Verbose logging
ARNIKO_MAX_CONCURRENT_SCANS=4      # Parallel scan cap
```

## Running scanners

Each adapter auto-detects whether the external CLI is installed:

```bash
# Pre-install the CLIs you want Arniko to use
brew install gitleaks semgrep trivy bandit checkov grype
# or
apt-get install gitleaks …

# Arniko picks them up automatically
arniko scan --target /path/to/repo
```

If a CLI isn't present, Arniko skips it and logs a warning — no hard failure.

## Development

```bash
git clone https://github.com/dirghaai/arniko.git
cd arniko
pnpm install

pnpm typecheck     # 0 errors
pnpm test          # 56 tests passing
pnpm dev           # Server with hot-reload (tsx)
pnpm build         # tsc → dist/
```

## Contributing

Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and sign the [CLA](./CLA.md).

New scanner adapters are especially welcome — the pattern is easy:

```typescript
// src/scanners/myTool.ts
import { BaseScanner, ScanResult } from './baseScanner.js';

export class MyToolScanner extends BaseScanner {
  name = 'my-tool';
  async run(target: ScanTarget): Promise<ScanResult> {
    // 1. Check CLI is installed (this.requireCLI('my-tool'))
    // 2. Exec with child_process, capture stdout
    // 3. Parse into Finding[]
    // 4. Return { scanner: this.name, findings, metrics }
  }
}
```

Tests: `tests/scanners.test.ts` has the pattern for test-with-CLI-missing.

## Attribution

Arniko's LLM vulnerability taxonomy and several attack primitives trace to
**DeepTeam** by Confident AI Inc.
(Apache-2.0, https://github.com/confident-ai/deepteam). Full attribution
lives in [`NOTICE`](./NOTICE). Thank you to the DeepTeam maintainers.

## Sister projects in the Dirgha OS

This repo is one of several products under the [Dirgha AI OS](https://github.com/Dirgha-AI/Rama-I-Dirgha-AI-OS) umbrella. Each repo stands on its own; together they compose a full stack for builders.

| Repo | What it does | License |
|---|---|---|
| [`Rama-I-Dirgha-AI-OS`](https://github.com/Dirgha-AI/Rama-I-Dirgha-AI-OS) | Vision & roadmap for our agentic, sovereign AI operating system. | Apache-2.0 |
| [`dirgha-code`](https://github.com/Dirgha-AI/dirgha-code) | AI coding agent for your terminal. Your keys, your machine, any model. | FSL-1.1-MIT |
| [`writer-studio`](https://github.com/Dirgha-AI/writer-studio) | Long-form writing studio — science, fiction, screenplays, research. | Apache-2.0 |
| [`creator-studio`](https://github.com/Dirgha-AI/creator-studio) | Creator workspace — agents for production, posting, monetization. | Apache-2.0 |
| [`abundance-protocol`](https://github.com/Dirgha-AI/abundance-protocol) | Decentralized compute and labor network. Rent GPUs, run agents, settle on Bitcoin. | Apache-2.0 |

Visit the umbrella org at [github.com/Dirgha-AI](https://github.com/Dirgha-AI) or the product site at [dirgha.ai](https://dirgha.ai).

## License

**Apache License 2.0** — free for any use: personal, commercial, research, hosted, redistributed. No hidden restrictions. Full text in [`LICENSE`](./LICENSE).

**Dirgha LLC owns the “Dirgha” name, logo, and product family** as registered trademarks. The code is open — the brand isn't. Forks of this repository must rename the product and remove Dirgha branding before distribution. Reasonable nominative use (“a fork of Arniko”) is fine.

See [`LICENSE`](./LICENSE) for the full legal text. Related documents:

- [`SECURITY.md`](./SECURITY.md) — vulnerability disclosure policy.
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) — Contributor Covenant 2.1.
- [`SUPPORT.md`](./SUPPORT.md) — where to ask for help.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to send a PR.


## Contribute

- **Code** — fork, branch, PR against `main`. Recipes in [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **Bugs** — file an issue using the [bug template](https://github.com/dirghaai/arniko/issues/new?template=bug.md).
- **Features** — file an issue using the [feature template](https://github.com/dirghaai/arniko/issues/new?template=feature.md).
- **Questions** — open a [Discussion](https://github.com/dirghaai/arniko/discussions) rather than an issue.
- **Security** — email `security@dirgha.ai`. Do NOT file a public issue for vulnerabilities.
- **Sponsor** — [dirgha.ai/contribute](https://dirgha.ai/contribute) · Lightning, GitHub Sponsors, OpenCollective.


## Links

| | |
|---|---|
| Website | [https://dirgha.ai/arniko](https://dirgha.ai/arniko) |
| Repository | [github.com/dirghaai/arniko](https://github.com/dirghaai/arniko) |
| Issues | [github.com/dirghaai/arniko/issues](https://github.com/dirghaai/arniko/issues) |
| Discussions | [github.com/dirghaai/arniko/discussions](https://github.com/dirghaai/arniko/discussions) |
| Security | `security@dirgha.ai` |
| Enterprise | `enterprise@dirgha.ai` |
| Press / general | `hello@dirgha.ai` |

---

**Arniko** is part of the Dirgha OS — open-source infrastructure for builders, shipped by a small bootstrapped team.

Named after Arniko of Nepal — the 13th-century master craftsman who brought the pagoda to Tibet and China. A scanner of ages, inspecting what others overlooked.

Built by [Dirgha LLC](https://dirgha.ai) in India. Open to the world.

Released under **Apache-2.0** · Copyright © 2026 Dirgha LLC · All third-party trademarks are property of their owners.

---

## 🌐 The Dirgha Ecosystem

**[Dirgha AI OS](https://github.com/Dirgha-AI/Rama-I-Dirgha-AI-OS)** — the agentic operating system. *Accelerate Abundance.*

| Repo | What it does |
|---|---|
| [Rama-I-Dirgha-AI-OS](https://github.com/Dirgha-AI/Rama-I-Dirgha-AI-OS) | Vision & roadmap for our agentic, sovereign AI operating system |
| [dirgha-code](https://github.com/Dirgha-AI/dirgha-code) | AI coding agent for your terminal |
| [writer-studio](https://github.com/Dirgha-AI/writer-studio) | Long-form writing studio — science, fiction, screenplays, research |
| [creator-studio](https://github.com/Dirgha-AI/creator-studio) | Creator workspace — agents for production, posting, monetization |
| [abundance-protocol](https://github.com/Dirgha-AI/abundance-protocol) | Decentralized compute and labor network |
| [arniko](https://github.com/Dirgha-AI/arniko) | AI security scanner — every tool, one unified report |
| [.github](https://github.com/Dirgha-AI/.github) | Org profile and community configuration |

- **Live platform:** [dirgha.ai](https://dirgha.ai) — chat, IDE, writer, research, library, marketplace, creator, education, manufacturing
- **Organization:** [github.com/Dirgha-AI](https://github.com/Dirgha-AI)
- **Partnerships:** [partner@dirgha.ai](mailto:partner@dirgha.ai)

*Dirgha — Accelerate Abundance. Built in India, for the world.*
