"""Diff-aware Hacktron dependency report for PRs.

Compares dependency manifests (base branch vs PR head) across one or more
projects in the same repo, takes the union of packages ADDED or CHANGED,
queries the Hacktron dependency verdict API for each, and writes a single
sticky markdown comment that aggregates the findings.

Supported ecosystems and manifests (auto-detected from the file name):
  npm   - pnpm-lock.yaml
  pypi  - pyproject.toml, uv.lock, requirements.txt

Design follows the Socket / Semgrep convention:
  - only report on packages newly introduced by THIS PR
  - single sticky comment, identified by an HTML marker comment
  - malicious -> block the check; suspicious -> advisory only

Inputs (env):
  HFW_SERVER                  default https://api-staging.hacktron.ai/v1/hfw
  HFW_PUBLIC_BASE_URL         default https://hfw.hacktron.ai

  Multi-project mode (preferred):
    HFW_PROJECTS              JSON list of project dicts:
                              [{"label": "root", "base": "...", "head": "...",
                                "ecosystem": "auto"}, ...]

  Single-project mode (back-compat):
    HFW_BASE_LOCKFILE         path to base-branch manifest (may be empty)
    HFW_HEAD_LOCKFILE         path to PR-head manifest
    HFW_ECOSYSTEM             npm|pypi|auto (default auto)

  HFW_VERDICT_WAIT_SECONDS    seconds to wait for in-progress scans (default 0)
  HFW_PARALLEL                concurrent verdict requests (default 4)
  HFW_IGNORE_FILE             optional allowlist (one name@version per line)
  HFW_REPORT_OUT              where to write the comment markdown

Outputs (GITHUB_OUTPUT):
  malicious_count, suspicious_count, diff_count, comment_path,
  ecosystems (comma-separated), projects_scanned
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HFW_SERVER = os.environ.get(
    "HFW_SERVER", "https://api-staging.hacktron.ai/v1/hfw"
).rstrip("/")
HFW_PUBLIC_BASE_URL = os.environ.get(
    "HFW_PUBLIC_BASE_URL", "https://hfw.hacktron.ai"
).rstrip("/")
PARALLEL = int(os.environ.get("HFW_PARALLEL", "4"))
WAIT_SECONDS = int(os.environ.get("HFW_VERDICT_WAIT_SECONDS", "0"))
SCAN_MODE = os.environ.get("HFW_SCAN_MODE", "").strip().lower()
ECOSYSTEM = os.environ.get("HFW_ECOSYSTEM", "auto").lower()
BASE_LOCKFILE = Path(os.environ.get("HFW_BASE_LOCKFILE", ".hfw-tmp/base-lock.yaml"))
HEAD_LOCKFILE = Path(os.environ.get("HFW_HEAD_LOCKFILE", "pnpm-lock.yaml"))
IGNORE_FILE = Path(os.environ.get("HFW_IGNORE_FILE", ".hfwignore"))
OUT_PATH = Path(os.environ.get("HFW_REPORT_OUT", ".hfw-tmp/comment.md"))

STICKY_MARKER = "<!-- hacktron-dependency-scan-comment -->"


SUPPORTED_MANIFESTS = {
    "pnpm-lock.yaml": "npm",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pyproject.toml": "pypi",
    "uv.lock": "pypi",
}


def detect_ecosystem(path: Path) -> str | None:
    """Map a manifest filename to its registry, or None if unsupported.

    Only manifests we actually have a parser for are listed. requirements.txt
    is matched by prefix because its name varies (requirements-dev.txt etc.).
    """
    name = path.name.lower()
    if name in SUPPORTED_MANIFESTS:
        return SUPPORTED_MANIFESTS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pypi"
    if path.parent.name == "requirements" and name.endswith(".txt"):
        return "pypi"
    return None


AUTH_FAIL_CODES = {401, 403}


# Package-name / version validators. Lockfile contents are attacker-controlled
# (a malicious PR can put anything in pnpm-lock.yaml / uv.lock / etc.), and we
# splice them into the URL path of an authenticated request to the verdict
# server. Without validation, an entry like `../../admin/foo` would traverse
# out of `/v1/verdict/{ecosystem}/...` and hit unrelated endpoints. Validate
# first; reject anything that doesn't look like a real package coordinate.
_NPM_NAME_RE = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$", re.IGNORECASE
)
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-+~!]*$")


def _validate_coord(ecosystem: str, name: str, version: str) -> str | None:
    """Return None if (name, version) look like a real package coordinate,
    otherwise return a short human-readable rejection reason."""
    pattern = _NPM_NAME_RE if ecosystem == "npm" else _PYPI_NAME_RE
    if not pattern.fullmatch(name):
        return f"invalid {ecosystem} package name {name!r}"
    if not _VERSION_RE.fullmatch(version):
        return f"invalid version {version!r}"
    return None


def _verdict_api_base() -> str:
    parsed = urllib.parse.urlparse(HFW_SERVER)
    if parsed.path.rstrip("/").endswith("/v1/hfw"):
        return HFW_SERVER
    return f"{HFW_SERVER}/v1"


def _verdict_url(ecosystem: str, name: str, version: str, wait: int) -> str:
    """Build the /v1/verdict URL with per-segment encoding.

    `name` is split on the single permitted `/` (scoped-npm separator) and each
    half is quoted with safe='@' so any stray slash that somehow slipped past
    validation is still percent-encoded. The verdict server route is declared
    with `{package:path}` so it accepts the literal-slash form for scoped names.
    """
    parts = name.split("/", 1)
    encoded_name = "/".join(urllib.request.quote(p, safe="@") for p in parts)
    scan_mode_query = (
        f"&scan_mode={urllib.request.quote(SCAN_MODE, safe='')}" if SCAN_MODE else ""
    )
    return (
        f"{_verdict_api_base()}/verdict/{ecosystem}/{encoded_name}"
        f"?version={urllib.request.quote(version, safe='')}"
        f"&wait_seconds={wait}"
        f"{scan_mode_query}"
    )


def _package_detail_url(ecosystem: str, name: str, version: str) -> str:
    parts = name.split("/", 1)
    encoded_name = "/".join(urllib.request.quote(p, safe="@") for p in parts)
    return (
        f"{HFW_PUBLIC_BASE_URL}/package/{ecosystem}/{encoded_name}"
        f"?version={urllib.request.quote(version, safe='')}"
    )


def http_get_json(url: str, timeout: float) -> tuple[int, dict, str | None]:
    """Return (http_status, body_json, error_message). error_message is None
    on a clean HTTP response (even 4xx with JSON body)."""
    headers = {"User-Agent": "hfw-ci-report/1.0"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(body), None
            except json.JSONDecodeError:
                return resp.status, {}, f"non-json body (status={resp.status})"
    except urllib.error.HTTPError as exc:
        try:
            return (
                exc.code,
                json.loads(exc.read().decode("utf-8", errors="replace")),
                None,
            )
        except Exception:
            return exc.code, {}, f"http error {exc.code}"
    except Exception as exc:
        return -1, {}, str(exc)


def parse_pnpm_lock(path: Path) -> set[tuple[str, str]]:
    """Return distinct (name, version) tuples from a pnpm v9 lockfile.

    pnpm v9 keys in `packages:` look like '/<name>@<version>(...peers...)'.
    We strip the leading slash and any peer-dep suffix in parens. We skip
    workspace / link / file refs because those aren't registry packages.
    """
    if not path.exists() or not path.stat().st_size:
        return set()

    text = path.read_text()
    out: set[tuple[str, str]] = set()
    in_packages = False
    key_re = re.compile(r"^\s+['\"]?(?P<spec>@?[A-Za-z0-9._\-/+]+@[^\s'\"():]+)")
    workspace_markers = ("link:", "file:", "workspace:", "github:")
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line:
            continue

        if not line.startswith(" ") and not line.startswith("\t"):
            in_packages = line.strip().rstrip(":") == "packages"
            continue
        if not in_packages:
            continue

        # workspace / link / file / github refs aren't real registry versions
        # and the version regex would strip the colon, so check the raw line.
        if any(marker in raw_line for marker in workspace_markers):
            continue

        m = key_re.match(line)
        if not m:
            continue
        spec = m.group("spec")

        at = spec.rfind("@")
        if at <= 0:
            continue
        name = spec[:at]
        version = spec[at + 1 :]
        if not version:
            continue
        out.add((name, version))
    return out


def parse_package_lock_json(path: Path) -> set[tuple[str, str]]:
    """Return distinct (name, version) tuples from an npm `package-lock.json`.

    Handles both lockfile shapes npm has shipped:

    - v3 (npm 7+, default today): flat `packages` object whose keys are
      `node_modules/<name>` (or nested `node_modules/<parent>/node_modules/<child>`).
      We take the substring after the LAST `node_modules/` so nested copies of
      the same package each get counted, since each version is a distinct
      supply-chain coordinate.
    - v1 / v2 (npm <= 6): nested `dependencies` tree. We walk recursively.

    Workspace link entries (`"link": true`) and the root project entry (key
    `""`) are skipped -- they aren't registry packages.
    """
    if not path.exists() or not path.stat().st_size:
        return set()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return set()

    out: set[tuple[str, str]] = set()

    packages = data.get("packages")
    if isinstance(packages, dict):
        marker = "node_modules/"
        for key, meta in packages.items():
            if not key:
                continue
            if not isinstance(meta, dict):
                continue
            if meta.get("link"):
                continue
            version = meta.get("version")
            if not isinstance(version, str) or not version:
                continue
            idx = key.rfind(marker)
            if idx < 0:
                continue
            name = key[idx + len(marker) :]
            if name:
                out.add((name, version))
        return out

    def _walk(deps):
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and version:
                out.add((name, version))
            _walk(meta.get("dependencies"))

    _walk(data.get("dependencies"))
    return out


def parse_pyproject_toml(path: Path) -> set[tuple[str, str]]:
    """Pull pinned (name, version) tuples from a pyproject.toml.

    Walks every dep-list shape we've seen in the wild:

      PEP 621 (the standard):
        [project] dependencies              (list of PEP 508 strings)
        [project.optional-dependencies]     (table: extra -> list)

      PEP 735 (Python 2024+, used by uv / pip 24+):
        [dependency-groups]                 (table: group -> list)

      Poetry:
        [tool.poetry.dependencies]          (table: name -> "==1.2.3" / dict)
        [tool.poetry.group.<g>.dependencies]
        [tool.poetry.dev-dependencies]      (legacy poetry)

      PDM:
        [tool.pdm.dev-dependencies]         (table: group -> list)

    Only `==` exact pins are emitted; ranges aren't a single concrete version
    we can scan against. Poetry's `name = "1.2.3"` shorthand is treated as
    an exact pin (no range operator) since that's the registry version pip /
    uv would actually install.
    """
    if not path.exists() or not path.stat().st_size:
        return set()

    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        return set()

    out: set[tuple[str, str]] = set()

    project = data.get("project") or {}
    for entry in project.get("dependencies") or []:
        pin = _pep508_pin(str(entry))
        if pin:
            out.add(pin)

    optional = project.get("optional-dependencies") or {}
    if isinstance(optional, dict):
        for extras_list in optional.values():
            for entry in extras_list or []:
                pin = _pep508_pin(str(entry))
                if pin:
                    out.add(pin)

    dep_groups = data.get("dependency-groups") or {}
    if isinstance(dep_groups, dict):
        for group_list in dep_groups.values():
            for entry in group_list or []:
                if not isinstance(entry, str):
                    continue
                pin = _pep508_pin(entry)
                if pin:
                    out.add(pin)

    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}
    out.update(_poetry_pins_from_table(poetry.get("dependencies")))
    out.update(_poetry_pins_from_table(poetry.get("dev-dependencies")))
    for group in (poetry.get("group") or {}).values():
        if isinstance(group, dict):
            out.update(_poetry_pins_from_table(group.get("dependencies")))

    pdm = tool.get("pdm") or {}
    pdm_dev = pdm.get("dev-dependencies") or {}
    if isinstance(pdm_dev, dict):
        for group_list in pdm_dev.values():
            for entry in group_list or []:
                if not isinstance(entry, str):
                    continue
                pin = _pep508_pin(entry)
                if pin:
                    out.add(pin)

    return out


def _poetry_pins_from_table(table) -> set[tuple[str, str]]:
    """Poetry stores deps as a table (`name = "1.2.3"` or `name = {...}`)
    rather than a PEP 508 list. Extract the exact-pin form."""
    if not isinstance(table, dict):
        return set()
    out: set[tuple[str, str]] = set()
    for name, spec in table.items():
        if name == "python":
            continue
        version = None
        if isinstance(spec, str):
            version = spec
        elif isinstance(spec, dict):
            # Poetry uses git/path/url tables for direct refs -- not registry
            # pins, so skip them here (direct-ref detection handles them).
            if any(k in spec for k in ("git", "path", "url")):
                continue
            version = spec.get("version")
        if not isinstance(version, str):
            continue
        # Poetry shorthand: bare "1.2.3" means exact. "^1.2" / "~1.2" / ">=1"
        # / "*" are ranges -- skip. Strip leading "==" if someone wrote it.
        v = version.strip()
        if v.startswith("=="):
            v = v[2:].strip()
        if not v or any(c in v for c in "^~><*,|"):
            continue
        out.add((str(name).lower(), v))
    return out


_PEP508_PIN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\[[^\]]+\])?"
    r"\s*==\s*"
    r"(?P<version>[A-Za-z0-9_.\-+!]+)"
)


def _pep508_pin(entry: str) -> tuple[str, str] | None:
    head = entry.split(";", 1)[0]
    m = _PEP508_PIN.match(head)
    if not m:
        return None
    return m.group("name").lower(), m.group("version")


UV_LOCAL_SOURCE_KEYS = ("editable", "directory", "virtual")


def parse_uv_lock(path: Path) -> set[tuple[str, str]]:
    """Pull every (name, version) tuple from a uv.lock (TOML).

    Skips entries whose `source` is local rather than a registry:
      - `editable = "."`            (the project being built, in -e mode)
      - `directory = "./packages/x"` (a sibling workspace member)
      - `virtual = "..."`           (uv's placeholder for a workspace root)
    These aren't real registry packages, and querying them just adds noise
    ("unknown verdict" rows for our own code) to the PR comment.
    """
    if not path.exists() or not path.stat().st_size:
        return set()
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        return set()
    out: set[tuple[str, str]] = set()
    for pkg in data.get("package") or []:
        source = pkg.get("source") or {}
        if isinstance(source, dict) and any(k in source for k in UV_LOCAL_SOURCE_KEYS):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if isinstance(name, str) and isinstance(version, str):
            out.add((name.lower(), version))
    return out


def parse_requirements_txt(path: Path) -> set[tuple[str, str]]:
    """Pull `<name>==<version>` lines from a requirements.txt."""
    if not path.exists() or not path.stat().st_size:
        return set()
    out: set[tuple[str, str]] = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parsed = _pep508_pin(line)
        if parsed:
            out.add(parsed)
    return out


# Direct-reference forms in PEP 508 / pip syntax that point at arbitrary URLs
# or git repos. These bypass the registry entirely, so a malicious PR can
# swap a pinned PyPI dep for a hostile git URL without us noticing.
# We capture them separately and surface them in the PR comment as
# suspicious-by-construction (cannot verdict-check a private URL).
_PEP508_DIRECT_REF = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\[[^\]]+\])?"
    r"\s*@\s*"
    r"(?P<ref>\S+)"
)
_PIP_VCS_LINE = re.compile(
    r"^\s*(?:-e\s+)?"
    r"(?P<scheme>git|hg|svn|bzr)\+[^#\s]+"
    r"(?:#egg=(?P<name>[A-Za-z0-9_.\-]+))?"
)
_PIP_URL_TARBALL = re.compile(
    r"^\s*(?:-e\s+)?(?P<url>https?://\S+\.(?:tar\.gz|whl|zip))"
)


def _direct_ref_from_line(line: str) -> tuple[str, str] | None:
    """Return (name, ref_url) if the line is a PEP 508 / pip direct reference.

    Recognises three shapes:
      1. PEP 508 direct refs: `foo @ git+https://...` or `foo @ https://...`
      2. Pip VCS lines:       `git+https://...#egg=foo` or `-e git+https://...`
      3. Pip tarball / wheel URLs: `https://host/foo-1.0.tar.gz`
    """
    m = _PEP508_DIRECT_REF.match(line)
    if m:
        return m.group("name").lower(), m.group("ref")
    m = _PIP_VCS_LINE.match(line)
    if m:
        name = (m.group("name") or "").lower()
        if not name:
            return None
        return name, line.strip()
    m = _PIP_URL_TARBALL.match(line)
    if m:
        url = m.group("url")
        # tarball name `pkg-1.0.tar.gz` → guess package name from the file stem.
        # Best-effort; if we can't, drop it so we don't synthesize a bogus name.
        from pathlib import PurePosixPath

        stem = PurePosixPath(url).name
        guess = stem.split("-", 1)[0]
        if not guess:
            return None
        return guess.lower(), url
    return None


_REQUIREMENTS_COMMENT = re.compile(r"(?:^|\s)#.*$")


def _strip_requirements_comment(line: str) -> str:
    """Drop trailing `#` comments without eating `#egg=foo` URL fragments.

    Per pip docs, an inline comment must be preceded by whitespace; a `#` in
    the middle of a URL (e.g. `git+...#egg=foo`) is part of the value, not a
    comment.
    """
    return _REQUIREMENTS_COMMENT.sub("", line).strip()


def parse_requirements_direct_refs(path: Path) -> set[tuple[str, str]]:
    """Return (name, ref_url) tuples for every direct-reference line.

    These are NOT registry pins -- we can't verdict-check them. The caller
    is expected to surface them as suspicious-by-construction in the report.
    """
    if not path.exists() or not path.stat().st_size:
        return set()
    out: set[tuple[str, str]] = set()
    for raw_line in path.read_text().splitlines():
        line = _strip_requirements_comment(raw_line)
        if not line:
            continue
        # skip lines we already capture cleanly as `name==version`
        if _pep508_pin(line):
            continue
        ref = _direct_ref_from_line(line)
        if ref:
            out.add(ref)
    return out


def parse_pyproject_direct_refs(path: Path) -> set[tuple[str, str]]:
    """Same idea, but for `[project].dependencies` direct refs in pyproject.toml."""
    if not path.exists() or not path.stat().st_size:
        return set()
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        return set()
    out: set[tuple[str, str]] = set()
    project = data.get("project") or {}
    candidates: list[str] = list(project.get("dependencies") or [])
    optional = project.get("optional-dependencies") or {}
    if isinstance(optional, dict):
        for v in optional.values():
            candidates.extend(v or [])
    for entry in candidates:
        if not isinstance(entry, str):
            continue
        head = entry.split(";", 1)[0].strip()
        if _pep508_pin(head):
            continue
        ref = _direct_ref_from_line(head)
        if ref:
            out.add(ref)
    return out


def parse_manifest(path: Path, ecosystem: str) -> set[tuple[str, str]]:
    name = path.name.lower()
    if ecosystem == "npm":
        if name == "pnpm-lock.yaml":
            return parse_pnpm_lock(path)
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            return parse_package_lock_json(path)
        raise UnsupportedManifestError(
            f"npm manifest {name!r} is not supported yet. "
            f"Supported npm lockfiles: pnpm-lock.yaml, package-lock.json, "
            f"npm-shrinkwrap.json. "
            f"yarn.lock has a different shape and needs a dedicated parser."
        )
    if ecosystem == "pypi":
        if name == "uv.lock":
            return parse_uv_lock(path)
        if name == "pyproject.toml":
            return parse_pyproject_toml(path)
        if name.endswith(".txt"):
            return parse_requirements_txt(path)
        raise UnsupportedManifestError(
            f"pypi manifest {name!r} is not recognized. Supported: pyproject.toml, "
            f"uv.lock, requirements*.txt, requirements/*.txt, or another .txt file "
            f"when ecosystem is explicitly pypi."
        )
    raise UnsupportedManifestError(f"unsupported ecosystem: {ecosystem!r}")


class UnsupportedManifestError(Exception):
    """Raised when we can't parse the given manifest file."""


def diff_lockfiles(base: Path, head: Path, ecosystem: str) -> list[tuple[str, str]]:
    base_set = parse_manifest(base, ecosystem)
    head_set = parse_manifest(head, ecosystem)
    return sorted(head_set - base_set)


def diff_direct_refs(base: Path, head: Path) -> list[tuple[str, str]]:
    """Return direct-reference (name, ref_url) tuples added or changed in head.

    Only requirements-style .txt files and pyproject.toml are scanned; the
    lockfile-style manifests (uv.lock, pnpm-lock, package-lock) bake exact
    registry versions so direct refs aren't a concern there.
    """
    base_name = head.name.lower()
    if base_name == "pyproject.toml":
        base_refs = parse_pyproject_direct_refs(base)
        head_refs = parse_pyproject_direct_refs(head)
    elif base_name.endswith(".txt"):
        base_refs = parse_requirements_direct_refs(base)
        head_refs = parse_requirements_direct_refs(head)
    else:
        return []
    return sorted(head_refs - base_refs)


def load_ignore(path: Path) -> set[tuple[str, str]]:
    if not path.exists():
        return set()
    out: set[tuple[str, str]] = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        at = line.rfind("@")
        if at <= 0:
            continue
        out.add((line[:at], line[at + 1 :]))
    return out


def probe(ecosystem: str, name: str, version: str) -> dict:
    """Ask the verdict server for an opinion. Polls in 8s windows (server's
    max wait per request) until the total budget WAIT_SECONDS is exhausted.

    `error` is set when the request never produced a usable verdict (network
    failure, auth, 5xx). `level` is "unknown" when the server simply hasn't
    finished scanning in time -- those two cases are very different and
    main() treats `error` as a hard failure but `unknown` as advisory.
    """
    coord_error = _validate_coord(ecosystem, name, version)
    if coord_error:
        return {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "http": -1,
            "verdict_status": None,
            "level": "unknown",
            "summary": "",
            "cached": False,
            "error": coord_error,
        }

    deadline = WAIT_SECONDS
    per_request_wait = min(8, max(1, deadline))
    last_body: dict = {}
    last_status = -1
    last_error: str | None = None
    spent = 0
    while True:
        url = _verdict_url(ecosystem, name, version, per_request_wait)
        status, body, err = http_get_json(url, timeout=per_request_wait + 10)
        last_status = status
        last_body = body
        last_error = err
        if err is not None and status in AUTH_FAIL_CODES:
            break
        if err is not None and status < 0:
            break
        verdict_status = body.get("status")
        if verdict_status not in {"pending", "scanning"}:
            break
        spent += per_request_wait
        if spent >= deadline:
            break

    # Any non-JSON body or unknown verdict status means the server didn't talk
    # to us properly. We explicitly demand a parseable verdict envelope before
    # declaring success.
    is_server_error = last_error is not None or not last_body.get("status")

    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "http": last_status,
        "verdict_status": last_body.get("status"),
        "level": (last_body.get("level") or "unknown"),
        "summary": (last_body.get("summary") or ""),
        "cached": last_body.get("cached", False),
        "error": last_error if is_server_error else None,
    }


def fetch_all(ecosystem: str, pkgs: list[tuple[str, str]]) -> list[dict]:
    if not pkgs:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        return list(pool.map(lambda nv: probe(ecosystem, *nv), pkgs))


def pkg_detail_url(ecosystem: str, name: str, version: str) -> str:
    return _package_detail_url(ecosystem, name, version)


def _table_row(r: dict, show_project: bool) -> str:
    summary = (r["summary"] or "—").replace("|", "\\|")[:180]
    project_cell = f"| `{r['label']}` " if show_project else ""
    url = pkg_detail_url(r["ecosystem"], r["name"], r["version"])
    return (
        f"{project_cell}| `{r['name']}` | `{r['version']}` | "
        f"{summary} | [view]({url}) |"
    )


def _table_header(show_project: bool) -> tuple[str, str]:
    if show_project:
        return (
            "| Project | Package | Version | Why | Details |",
            "|---|---|---|---|---|",
        )
    return (
        "| Package | Version | Why | Details |",
        "|---|---|---|---|",
    )


def render(
    projects: list[dict],
    results: list[dict],
    ignored_in_diff: set[tuple[str, str, str]],
) -> str:
    """Build the sticky comment.

    `projects` is the configured project list (used for the "scanned N projects"
    footer line). `results` and `ignored_in_diff` are tagged with `label` so
    we can attribute rows back to their lockfile.
    """
    malicious = [r for r in results if r["level"] == "malicious"]
    suspicious = [r for r in results if r["level"] == "suspicious"]
    clean = [r for r in results if r["level"] == "clean"]
    unknown = [
        r for r in results if r["level"] not in {"malicious", "suspicious", "clean"}
    ]

    multi = len(projects) > 1
    total_diff = len(results)

    lines: list[str] = [STICKY_MARKER, ""]
    lines.append("## Hacktron Dependency Scan")
    lines.append("")

    if not results:
        lines.append("No dependency changes detected in this PR.")
        if multi:
            scanned = ", ".join(f"`{p['label']}`" for p in projects)
            lines.append("")
            lines.append(f"<sub>Scanned {len(projects)} project(s): {scanned}</sub>")
        return "\n".join(lines) + "\n"

    if malicious:
        lines.append(
            "**Blocking — "
            f"{len(malicious)} malicious package(s) introduced by this PR.**"
        )
    elif suspicious:
        lines.append(
            f"Review — {len(suspicious)} suspicious package(s) introduced by "
            "this PR. Merge is allowed."
        )
    else:
        lines.append(f"All {total_diff} new/changed dependencies look clean.")
    lines.append("")

    lines.append(
        f"- added or changed: **{total_diff}**"
        f" · malicious: **{len(malicious)}**"
        f" · suspicious: **{len(suspicious)}**"
        f" · clean: **{len(clean)}**"
        f" · unknown: **{len(unknown)}**"
    )
    if ignored_in_diff:
        lines.append(
            "- allowlisted via `.hfwignore` "
            "(only counting entries in this PR's diff): "
            f"**{len(ignored_in_diff)}**"
        )
    if multi:
        scanned = ", ".join(f"`{p['label']}`" for p in projects)
        lines.append(f"- scanned {len(projects)} project(s): {scanned}")
    lines.append("")

    header, sep = _table_header(multi)

    if malicious:
        lines.append("### Malicious — blocks this PR")
        lines.append("")
        lines.append(header)
        lines.append(sep)
        for r in malicious:
            lines.append(_table_row(r, multi))
        lines.append("")

    if suspicious:
        lines.append("### Suspicious — review before merging")
        lines.append("")
        lines.append(header)
        lines.append(sep)
        for r in suspicious[:50]:
            lines.append(_table_row(r, multi))
        if len(suspicious) > 50:
            lines.append(f"_…and {len(suspicious) - 50} more suspicious package(s)_")
        lines.append("")

    if unknown:
        unk_preview = ", ".join(f"`{r['name']}@{r['version']}`" for r in unknown[:10])
        extra = f" (+{len(unknown) - 10} more)" if len(unknown) > 10 else ""
        lines.append(
            f"<details><summary>{len(unknown)} dependency(ies) had no verdict "
            "in time</summary>"
        )
        lines.append("")
        lines.append(f"{unk_preview}{extra}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append(
        "<sub>Scan covered only dependencies added or changed in this PR. "
        "False positive? Add a line to `.hfwignore` "
        "(one `name@version` per line).</sub>"
    )
    return "\n".join(lines) + "\n"


def write_output(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{key}={value}\n")


def _resolve_ecosystem(head: Path, requested: str) -> str | None:
    if requested in {"npm", "pypi"}:
        return requested
    return detect_ecosystem(head)


def _load_projects() -> list[dict] | None:
    """Parse HFW_PROJECTS JSON, or return None if not configured.

    Schema per entry:
    {"label": str, "base": str, "head": str, "ecosystem": "auto"|"npm"|"pypi"}.
    """
    raw = os.environ.get("HFW_PROJECTS")
    if not raw or not raw.strip():
        return None
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"::error::HFW_PROJECTS is not valid JSON: {exc}", file=sys.stderr)
        return []
    if not isinstance(items, list) or not items:
        print("::error::HFW_PROJECTS must be a non-empty JSON list.", file=sys.stderr)
        return []
    return items


def _single_project_from_env() -> list[dict]:
    return [
        {
            "label": HEAD_LOCKFILE.parent.name or "root",
            "base": str(BASE_LOCKFILE),
            "head": str(HEAD_LOCKFILE),
            "ecosystem": ECOSYSTEM,
        }
    ]


def main() -> int:
    projects = _load_projects()
    if projects is None:
        projects = _single_project_from_env()
    if not projects:
        return 2

    ignored = load_ignore(IGNORE_FILE)

    all_diff_entries: list[tuple[str, str, str, str]] = []
    ignored_in_diff: set[tuple[str, str, str]] = set()
    ecosystems_used: set[str] = set()
    synthetic_results: list[dict] = []

    for proj in projects:
        label = str(proj.get("label") or "root")
        base = Path(str(proj.get("base") or ""))
        head = Path(str(proj.get("head") or ""))
        requested = str(proj.get("ecosystem") or "auto").lower()
        ecosystem = _resolve_ecosystem(head, requested)
        if not ecosystem:
            print(
                f"::error::[{label}] could not determine ecosystem for {head.name}; "
                f"set `ecosystem` to npm or pypi.",
                file=sys.stderr,
            )
            return 2

        try:
            diff = diff_lockfiles(base, head, ecosystem)
        except UnsupportedManifestError as exc:
            print(f"::error::[{label}] {exc}", file=sys.stderr)
            return 2

        proj["ecosystem"] = ecosystem
        ecosystems_used.add(ecosystem)
        for name, version in diff:
            if (name, version) in ignored:
                ignored_in_diff.add((label, name, version))
                continue
            all_diff_entries.append((label, ecosystem, name, version))

        # Direct-reference dependencies (PEP 508 `pkg @ git+...` / pip VCS lines).
        # These never reach the verdict server (we can't scan an arbitrary URL),
        # but a malicious PR can use them to swap a clean PyPI dep for a hostile
        # repo without us noticing. Surface them as suspicious-by-construction.
        if ecosystem == "pypi":
            new_refs = diff_direct_refs(base, head)
            for ref_name, ref_url in new_refs:
                synthetic_results.append(
                    {
                        "label": label,
                        "ecosystem": ecosystem,
                        "name": ref_name,
                        "version": ref_url[:120],
                        "http": 0,
                        "verdict_status": "direct-reference",
                        "level": "suspicious",
                        "summary": (
                            "Direct reference dependency (PEP 508 / VCS URL). "
                            "Bypasses the registry; Hacktron cannot verify it. "
                            "Confirm the URL is trusted."
                        ),
                        "cached": False,
                        "error": None,
                    }
                )

        print(
            f"[hfw-report] [{label}] manifest={head.name}  ecosystem={ecosystem}  "
            f"diff={len(diff)} added/changed; "
            f"silenced={sum(1 for nv in diff if nv in ignored)}"
        )

    print(
        f"[hfw-report] querying verdicts for {len(all_diff_entries)} package(s) "
        f"(wait={WAIT_SECONDS}s, parallel={PARALLEL})"
    )

    # Probe each unique (ecosystem, name, version) once, then fan results back
    # out to every (label, ...) that asked for it. Saves N duplicate API hits
    # when the same package shows up in multiple sub-projects.
    unique_keys = sorted({(eco, n, v) for (_, eco, n, v) in all_diff_entries})
    verdicts_by_key: dict[tuple[str, str, str], dict] = {}
    if unique_keys:
        with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL) as pool:
            verdict_iter = pool.map(lambda k: probe(*k), unique_keys)
            for key, verdict in zip(unique_keys, verdict_iter, strict=True):
                verdicts_by_key[key] = verdict

    results: list[dict] = []
    for label, eco, name, version in all_diff_entries:
        v = verdicts_by_key.get((eco, name, version))
        if v is None:
            continue
        results.append({**v, "label": label})

    # Direct-reference dependencies bypass the verdict server entirely; they
    # were collected per-project above. Add them now so they show up in the
    # suspicious section of the comment alongside real verdicts.
    results.extend(synthetic_results)

    for r in sorted(results, key=lambda x: (x["level"], x["label"], x["name"])):
        suffix = (
            f"  (error: {r['error']})" if r["error"] else f"  ({r['verdict_status']})"
        )
        print(
            f"  [{r['label']:<14}] {r['level']:<10}  {r['name']}@{r['version']}{suffix}"
        )

    md = render(projects, results, ignored_in_diff)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(md, encoding="utf-8")

    malicious = sum(1 for r in results if r["level"] == "malicious")
    suspicious = sum(1 for r in results if r["level"] == "suspicious")
    errored = [r for r in results if r["error"]]

    write_output("malicious_count", str(malicious))
    write_output("suspicious_count", str(suspicious))
    write_output("diff_count", str(len(results)))
    write_output("error_count", str(len(errored)))
    write_output("comment_path", str(OUT_PATH))
    write_output("ecosystems", ",".join(sorted(ecosystems_used)))
    write_output("projects_scanned", str(len(projects)))

    print(
        f"[hfw-report] wrote {OUT_PATH}  "
        f"(projects={len(projects)}, malicious={malicious}, suspicious={suspicious}, "
        f"errors={len(errored)}, diff={len(results)})"
    )

    if errored:
        print(
            f"::error::Hacktron could not get verdicts for {len(errored)} package(s). "
            f"First error: [{errored[0]['label']}] "
            f"{errored[0]['name']}@{errored[0]['version']} "
            f"-> {errored[0]['error']}",
            file=sys.stderr,
        )
        if any(r["http"] in AUTH_FAIL_CODES for r in errored):
            print(
                "::error::Authentication failure while fetching Hacktron verdicts.",
                file=sys.stderr,
            )
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
