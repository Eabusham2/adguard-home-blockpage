# AdGuard Home Block Page

Follow the repository's [AGENTS.md](../AGENTS.md) for the module map, validation,
deployment boundaries, and release rules. This application uses Python's
standard library; there is no npm or pytest setup.

- From the repository root, run `python scripts/validate.py` and
  `git diff --check`. Use the dummy Compose validation commands in AGENTS.md
  for deployment changes.
- Importing `app.py` starts its HTTP listener. Inspect it statically or use an
  isolated subprocess; the existing validation script manages its own server.
- Keep the Portainer source pinned to one full commit SHA whose four runtime
  modules match the release. Runtime changes require updating both the stack's
  pin and its CI assertion after committing the intended module contents.
  Documentation-only edits do not require a changed pin or version.
- Preserve authorization and its documented additional IPv6 networks,
  same-host memory checks, serialized writes, and durable pending state.
  Never automatically repeat an uncertain allowlist update.
- Use isolated fixtures instead of a live AdGuard service. Document HTTP-only
  behavior accurately; `/healthz` is listener liveness, not proof of working DNS.
