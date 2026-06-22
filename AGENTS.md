# AGENTS.md

Guidance for coding agents working in this repository.

## Repo Map

- `action.yml` is the public composite GitHub Action entrypoint.
- `scripts/hfw_report.py` is the stdlib-only report client used by the action.
- `scripts/github_action/` contains helper scripts for input validation and
  manifest extraction.
- `tests/` covers parser behavior, report formatting, and action helper
  contracts.
- `.github/workflows/ci.yml` is the required quality gate for the public repo.

## Contracts

- The action is fast-mode only and uses Hacktron's public API proxy:
  `https://api.hacktron.ai/v1/hfw`.
- Do not add Cloudflare Access inputs or require repository secrets for the
  default public dependency scan.
- Keep `action.yml` thin. Put parsing, validation, and JSON handling in Python
  helper scripts.
- `scripts/hfw_report.py` intentionally uses only the Python standard library
  because it runs inside arbitrary caller repositories.
- Preserve stable PR comments: keep the sticky marker, deterministic sorting,
  manifest order, and dedupe behavior unless explicitly changing the contract.

## Development

- Use locked uv commands:
  - `uv sync --locked --group dev`
  - `uv run --locked ruff format --check .`
  - `uv run --locked ruff check .`
  - `uv run --locked pytest`
- When editing action helper scripts, test them from a temporary git repository
  as well as with unit tests; the action runs in the caller's checkout.
- Treat lockfile contents as attacker-controlled PR input. Validate package
  names and versions before constructing API URLs.
- Keep docs Marketplace-ready: usage example, permissions, inputs, outputs,
  failure behavior, and release instructions should stay current.
