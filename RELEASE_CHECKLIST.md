# Cyber Swarm Release Checklist

Use this checklist before publishing a release tarball or npm package.

## 1. Automated tests

- [ ] `npm run typecheck`
- [ ] `npm run build`
- [ ] `npm run test`
- [ ] `cd agent_runtime && python -m pytest`

## 2. Demo smoke

- [ ] `npm link` (or install from tarball)
- [ ] `swarm --help` prints command list
- [ ] `swarm doctor` prints version, Node, config status
- [ ] `swarm init` in a clean sample repo
- [ ] `swarm demo . --from-cache` replays without model calls (after one prior demo run)

## 3. No secrets in package

- [ ] `.env` is not tracked and not in tarball
- [ ] `.swarm/reports/` and `.swarm/cache/` are not in tarball
- [ ] `skills/external/` is not in tarball
- [ ] No raw API keys or tokens in shipped source
- [ ] Test fixtures use `<REDACTED_SECRET>` placeholders only

## 4. Package validation

- [ ] `npm run pack:check` passes
- [ ] `npm pack --dry-run` lists only intended paths (`dist/`, `agent_runtime/cyber_swarm/`, docs, LICENSE, `.env.example`)
- [ ] `dist/cli/index.js` starts with `#!/usr/bin/env node`
- [ ] Compiled test files (`*.test.js`) are not in tarball

## 5. npm link smoke

- [ ] `npm link` from repo root
- [ ] `swarm --help` works from another directory
- [ ] `swarm doctor` resolves package version correctly
- [ ] `npm unlink -g cyber-swarm` when finished

## 6. Tarball install smoke (optional)

```bash
npm run build
npm pack
npm install -g ./cyber-swarm-0.1.0.tgz
swarm --help
npm uninstall -g cyber-swarm
```

## 7. Version bump

- [ ] Update `package.json` version
- [ ] Update `agent_runtime/pyproject.toml` version if needed
- [ ] Tag release in git after checklist passes
