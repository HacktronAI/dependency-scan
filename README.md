# Hacktron Dependency Scan GitHub Action

Diff-aware supply-chain scanning for pull requests. The action checks npm and
PyPI dependencies added or changed by a PR against Hacktron's public malware
feed, posts a summary of dependency changes, and fails the workflow when [malicious
packages](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
are introduced.

The default scan is free to run, fast-mode only, and does not require an API
key.

## Usage

Create `.github/workflows/hacktron-dependency-scan.yml`:

```yaml
name: Hacktron Dependency Scan

on:
  pull_request:
    paths:
      - "**/package-lock.json"
      - "**/pnpm-lock.yaml"
      - "**/npm-shrinkwrap.json"
      - "**/pyproject.toml"
      - "**/uv.lock"
      - "**/requirements*.txt"
      - "**/requirements/*.txt"

permissions:
  contents: read
  pull-requests: write

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: HacktronAI/dependency-scan@v1
```

## What It Scans

The action compares the base branch manifest to the PR manifest and scans only
packages that were added or changed by the PR. Supported manifests:

| Ecosystem | Files                                                                  |
| --------- | ---------------------------------------------------------------------- |
| npm       | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`           |
| PyPI      | `pyproject.toml`, `uv.lock`, `requirements*.txt`, `requirements/*.txt` |

If no `lockfile` or `lockfiles` input is set, supported manifests are
auto-discovered from tracked files.

## Outcomes

- `SUCCEEDED`: no malicious packages were introduced.
- `FAILED`: one or more malicious packages were introduced and
  `fail-on-malicious` is enabled.
- `ERROR`: the action could not parse manifests, call the public API, or post
  the PR comment.

Suspicious package signals are shown in the PR comment, but only malicious
packages fail the workflow by default.

## Inputs

| Input               | Default      | Description                                                                      |
| ------------------- | ------------ | -------------------------------------------------------------------------------- |
| `lockfile`          | empty        | Single manifest to scan. Mutually exclusive in practice with `lockfiles`.        |
| `lockfiles`         | empty        | Newline-separated manifest paths or bash-style path patterns.                    |
| `ignore-file`       | `.hfwignore` | Optional allowlist file, one `name@version` per line.                            |
| `fail-on-malicious` | `true`       | Fail the check when malicious packages are introduced. Allowed: `true`, `false`. |

## Outputs

| Output             | Description                                               |
| ------------------ | --------------------------------------------------------- |
| `malicious_count`  | Number of malicious packages introduced by the PR.        |
| `suspicious_count` | Number of suspicious packages introduced by the PR.       |
| `diff_count`       | Total added or changed packages considered by the action. |

## Selecting Manifests

Scan one file:

```yaml
- uses: HacktronAI/dependency-scan@v1
  with:
    lockfile: services/api/pnpm-lock.yaml
```

Scan explicit files or patterns:

```yaml
- uses: HacktronAI/dependency-scan@v1
  with:
    lockfiles: |
      pnpm-lock.yaml
      services/*/package-lock.json
      requirements/*.txt
```

## Allowlisting

Create `.hfwignore` at the repository root to suppress known false positives:

```text
some-package@1.2.3
@scope/package@4.5.6
```

Allowlisted packages are still parsed, but they do not fail the workflow.

## Required Permissions

Use:

```yaml
permissions:
  contents: read
  pull-requests: write
```

`contents: read` is required to read manifests and compare against the base
branch. `pull-requests: write` is required only for the sticky PR comment. If
you remove comment posting in a forked workflow, `contents: read` is enough for
the scan itself.

## Development

Install tooling:

```bash
uv sync --locked --group dev
```

Run checks:

```bash
uv run --locked ruff format --check .
uv run --locked ruff check .
uv run --locked pytest
python -c "import yaml; yaml.safe_load(open('action.yml'))"
git diff --check
```

Install pre-commit hooks:

```bash
uv run --locked pre-commit install
```

Run hooks manually:

```bash
uv run --locked pre-commit run --all-files
```

## Release

1. Update the README if inputs, outputs, or behavior changed.
2. Run the full local check suite.
3. Merge to `main`.
4. Create a semver tag such as `v1.0.0`.
5. Move or create the major tag, such as `v1`, to the same commit.
6. Draft a GitHub release from the semver tag.

Marketplace users should pin to a major tag (`@v1`) or exact version
(`@v1.0.0`) depending on their update policy.
