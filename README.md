# Cyber Swarm

CLI-first autonomous security swarm for **authorized pre-production testing**. Cyber Swarm scans a target repository, routes security playbooks, runs graph-backed specialists with strict verification, and produces demo-ready findings with redacted evidence.

## Requirements

- **Node.js** 20+
- **Python** 3.11+ (for the LangGraph agent runtime)
- **Git** (for `swarm skills sync`)

## Install

### Local development (from this repo)

```bash
git clone https://github.com/MrSujalThapa/microCraftHacks.git
cd microCraftHacks
npm install
npm run build
npm link
```

Verify the CLI:

```bash
swarm --help
swarm doctor
swarm init
```

Run a cached demo replay (no model calls) against the current directory:

```bash
swarm demo . --from-cache
```

Use `npm run dev -- <command>` if you prefer running from TypeScript sources without linking.

### Install from a package tarball

```bash
npm run build
npm pack
npm install -g ./cyber-swarm-0.1.0.tgz
swarm --help
```

### Future npm install

When published to npm:

```bash
npm install -g cyber-swarm
swarm --help
```

## Environment variables

Copy `.env.example` to `.env` in your **target project** (never commit `.env`):

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | Required when `provider` is `openai` (default) |
| `SWARM_PROVIDER` | Override provider (`openai`, `mock`, `local`) |
| `SWARM_MODEL` | Override model (default `gpt-5-mini`) |

Provider and model can also be set in `.swarm/config.json` after `swarm init`.

Install Python runtime dependencies once:

```bash
pip install -e agent_runtime
```

## Quick start

```bash
swarm init
swarm skills sync
swarm skills index
swarm scan .
swarm demo .              # full demo (uses provider)
swarm demo . --from-cache # replay cached findings, no model calls
swarm findings --demo
swarm findings --best
swarm explain <finding-id>
swarm fix <finding-id>
```

## Safety and authorized use

Cyber Swarm is designed for **systems you own or have explicit written authorization to test**. It performs static analysis and safe reproduction guidance — not live exploitation against third-party systems.

- Use `mock` provider for offline demos and CI smoke tests.
- Findings redact secret-like values in CLI output; rotate any exposed credentials immediately.
- Review rejected findings and verifier notes before acting on results.

## Python runtime

The Node CLI shells out to `agent_runtime/` (bundled in the npm package). When developing inside this monorepo, a local `agent_runtime/` directory takes precedence over the packaged copy.

## Release validation

Before tagging a release, follow [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md).

```bash
npm run typecheck
npm run build
npm run test
npm run pack:check
cd agent_runtime && python -m pytest
```

## License

MIT — see [LICENSE](./LICENSE).
