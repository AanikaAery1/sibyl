#!/usr/bin/env python3
"""Dependency licence inventory and D15 gate for the Sibyl uv environment and the console.

Policy (DECISIONS D15, roadmap/project-shipper.md 3.4):
  * deny  AGPL, SSPL, BUSL, RSAL, Elastic, Commons Clause, GPL (not LGPL)
  * flag  LGPL, MPL, EPL, CDDL: weak copyleft, needs an explicit review
  * allow MIT, BSD, Apache-2.0, ISC, PSF, ... (permissive)
  * UNKNOWN fails, like a deny.
Only *bundled* (runtime) dependencies gate. Build/CI-only packages are listed.
A waiver (ci/licence-waivers.toml, one D-log reference each) turns a failure
into a recorded pass.

Two ecosystems, one gate: the Python packages (installed distributions; runtime = the
`uv export --no-dev` set) and the console's npm packages (`console/package-lock.json`;
runtime = what `npm ci --omit=dev` installs, i.e. every non-dev entry including optional
platform binaries). npm entries are keyed `npm:<name>` so a waiver never crosses ecosystems.

Usage (from ci/run.sh):
  uv export --all-packages --no-dev --no-hashes --format requirements-txt > rt.txt
  uv run python ci/licences.py --runtime-requirements rt.txt \
      --npm-lock console/package-lock.json --output out.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from importlib.metadata import distributions
from pathlib import Path

ALLOW = "allow"
FLAG = "flag"
DENY = "deny"
UNKNOWN = "unknown"
_RANK = {ALLOW: 0, FLAG: 1, UNKNOWN: 2, DENY: 3}

FIRST_PARTY_PREFIX = "sibyl"
DEFAULT_WAIVERS = Path(__file__).with_name("licence-waivers.toml")

_DENY_PATTERNS = (
    r"^AGPL",
    r"^SSPL",
    r"^BUSL",
    r"^RSAL",
    r"^Elastic",
    r"Commons-Clause",
    r"^GPL",
)
_FLAG_PATTERNS = (r"^LGPL", r"^MPL", r"^EPL", r"^CDDL")
_ALLOW_IDS = frozenset(
    {
        "MIT",
        "MIT-0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "0BSD",
        "Apache-2.0",
        "ISC",
        "PSF-2.0",
        "Python-2.0",
        "Unlicense",
        "Zlib",
        "CC0-1.0",
        "PostgreSQL",
        "BSD-3-Clause-Clear",
        "HPND",
        # Permissive, attribution only (npm): caniuse-lite data (runtime via Next's
        # browserslist) and the Blue Oak model licence.
        "CC-BY-4.0",
        "BlueOak-1.0.0",
    }
)
NPM = "npm"
PYPI = "pypi"

# Free text and trove classifiers seen in the wild, mapped to SPDX-ish ids.
_FREE_TEXT: tuple[tuple[str, str], ...] = (
    (r"affero", "AGPL-3.0"),
    (r"lesser general public license v3|lgplv3", "LGPL-3.0"),
    (r"lesser general public license v2|lgplv2", "LGPL-2.1"),
    (r"lesser general public|lgpl", "LGPL"),
    (r"general public license v3|gplv3", "GPL-3.0"),
    (r"general public license v2|gplv2", "GPL-2.0"),
    (r"general public license|\bgpl\b", "GPL"),
    (r"mozilla public license 2\.0|mpl[- ]?2\.0", "MPL-2.0"),
    (r"mozilla public license|\bmpl\b", "MPL"),
    (r"server side public license|sspl", "SSPL-1.0"),
    (r"business source license|busl", "BUSL-1.1"),
    (r"bsd 2-clause|bsd-2|simplified bsd", "BSD-2-Clause"),
    (r"bsd 3-clause|bsd-3|new bsd|revised bsd", "BSD-3-Clause"),
    (r"^bsd( license)?$", "BSD-3-Clause"),
    (
        r"apache( software)?( license)?[ ,-]*(version )?2(\.0)?$|^apache software license$",
        "Apache-2.0",
    ),
    (r"^mit( license)?$|^mit-0$|^expat$", "MIT"),
    (r"^isc( license)?( \(iscl\))?$", "ISC"),
    (r"python software foundation|^psf", "PSF-2.0"),
    (r"^the unlicense|^unlicense$", "Unlicense"),
)

# Container images: allowed by repository, with their licence (D15).
# Denied by repository regardless of tag; redis is allowed only below 7.4.
_IMAGE_ALLOW: dict[str, str] = {
    "postgres": "PostgreSQL",
    "library/postgres": "PostgreSQL",
    "ghcr.io/dexidp/dex": "Apache-2.0",
    "caddy": "Apache-2.0",
    "library/caddy": "Apache-2.0",
    "python": "PSF-2.0",
    "library/python": "PSF-2.0",
    "ghcr.io/astral-sh/uv": "MIT OR Apache-2.0",
    "valkey/valkey": "BSD-3-Clause",
    "node": "MIT",  # console build/runtime base (Node.js)
    "library/node": "MIT",
}
_IMAGE_DENY: dict[str, str] = {
    "minio": "AGPL-3.0",
    "zitadel": "AGPL-3.0",
    "timescale": "TSL",
    "grafana": "AGPL-3.0",
    "garage": "AGPL-3.0",
    "dxflrs": "AGPL-3.0",
    "elasticsearch": "Elastic/SSPL",
    "mongo": "SSPL-1.0",
}
_FIRST_PARTY_IMAGE = re.compile(r"^sibyl/[a-z0-9-]+$")


@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str = ""


@dataclass(frozen=True)
class ImageVerdict:
    allowed: bool
    licence: str
    reason: str


@dataclass(frozen=True)
class Dist:
    name: str
    version: str
    licence: str
    ecosystem: str = PYPI

    @property
    def key(self) -> str:
        """Gate key: PEP 503 name for Python, ``npm:<name>`` for console packages."""
        name = canonical_name(self.name)
        return name if self.ecosystem == PYPI else f"{self.ecosystem}:{name}"

    @property
    def label(self) -> str:
        return self.name if self.ecosystem == PYPI else f"{self.ecosystem}:{self.name}"


@dataclass(frozen=True)
class Entry:
    dist: Dist
    verdict: Verdict
    klass: str  # bundled | build/ci-only | first-party
    waiver: str | None = None

    @property
    def gating(self) -> bool:
        return self.klass == "bundled" and self.waiver is None

    @property
    def fails(self) -> bool:
        return self.gating and self.verdict.status in (DENY, UNKNOWN)


@dataclass(frozen=True)
class Report:
    entries: tuple[Entry, ...]
    unused_waivers: tuple[str, ...] = field(default=())

    @property
    def failures(self) -> list[Entry]:
        return [e for e in self.entries if e.fails]

    @property
    def flags(self) -> list[Entry]:
        return [e for e in self.entries if e.gating and e.verdict.status == FLAG]

    @property
    def exit_code(self) -> int:
        return 1 if self.failures else 0


# --- classification ----------------------------------------------------------------------


def canonical_name(name: str) -> str:
    """PEP 503 normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalise(raw: str) -> str:
    text = raw.strip()
    if text.startswith("License ::"):
        text = text.split("::")[-1].strip()
    if _classify_id(text).status != UNKNOWN:
        return text
    lowered = text.lower()
    for pattern, spdx in _FREE_TEXT:
        if re.search(pattern, lowered):
            return spdx
    return text


def _classify_id(identifier: str) -> Verdict:
    ident = identifier.strip().strip("()").strip()
    if not ident or ident.upper() == "UNKNOWN":
        return Verdict(UNKNOWN, "no licence metadata")
    if ident.startswith("LicenseRef-"):
        return Verdict(UNKNOWN, f"custom licence {ident}")
    if any(re.search(p, ident, re.I) for p in _FLAG_PATTERNS):
        return Verdict(FLAG, f"{ident}: weak copyleft, review required")
    if any(re.search(p, ident, re.I) for p in _DENY_PATTERNS):
        return Verdict(DENY, f"{ident}: on the D15 deny list")
    base = re.sub(r"\+$", "", ident)
    if base in _ALLOW_IDS:
        return Verdict(ALLOW)
    return Verdict(UNKNOWN, f"unrecognised licence {ident!r}")


def classify(expression: str) -> Verdict:
    """Classify an SPDX expression. OR takes the best option, AND the worst."""
    expr = expression.strip()
    if not expr:
        return Verdict(UNKNOWN, "no licence metadata")
    flat = expr.replace("(", " ").replace(")", " ")
    options = [o for o in re.split(r"\s+OR\s+", flat) if o.strip()]
    best: Verdict | None = None
    for option in options:
        terms = [t for t in re.split(r"\s+AND\s+|\s+WITH\s+", option) if t.strip()]
        worst = max((_classify_id(normalise(t)) for t in terms), key=lambda v: _RANK[v.status])
        if best is None or _RANK[worst.status] < _RANK[best.status]:
            best = worst
    return best or Verdict(UNKNOWN, "empty expression")


def licence_from_fields(
    expression: str | None, licence_field: str | None, classifiers: Iterable[str]
) -> str:
    if expression and expression.strip():
        return expression.strip()
    text = (licence_field or "").strip()
    if text and len(text) <= 80 and "\n" not in text:
        return normalise(text)
    for classifier in classifiers:
        leaf = classifier.split("::")[-1].strip()
        if classifier.startswith("License ::") and leaf != "OSI Approved":
            return normalise(leaf)
    return "UNKNOWN"


def split_image(ref: str) -> tuple[str, str]:
    """`ghcr.io/x/y:1.2@sha256:..` -> (`ghcr.io/x/y`, `1.2`)."""
    without_digest = ref.split("@", 1)[0]
    head, _, last = without_digest.rpartition("/")
    name, _, tag = last.partition(":")
    return (f"{head}/{name}" if head else name), tag


def image_verdict(ref: str) -> ImageVerdict:
    repo, tag = split_image(ref)
    if _FIRST_PARTY_IMAGE.match(repo):
        return ImageVerdict(True, "LicenseRef-Proprietary", "first-party image")
    for marker, lic in _IMAGE_DENY.items():
        if marker in repo:
            return ImageVerdict(False, lic, f"{repo} is excluded by D15")
    if repo in ("redis", "library/redis"):
        return _redis_verdict(tag)
    if repo in _IMAGE_ALLOW:
        return ImageVerdict(True, _IMAGE_ALLOW[repo], "allow-listed")
    return ImageVerdict(False, "UNKNOWN", f"{repo} is not on the image allow-list")


def _redis_verdict(tag: str) -> ImageVerdict:
    match = re.match(r"^(\d+)(?:\.(\d+))?", tag)
    if not match:
        return ImageVerdict(False, "RSAL/SSPL", "redis without a pinned version")
    major, minor = int(match.group(1)), int(match.group(2) or 0)
    if (major, minor) < (7, 4):
        return ImageVerdict(True, "BSD-3-Clause", "redis < 7.4")
    return ImageVerdict(False, "RSAL/SSPL/AGPL", "redis >= 7.4 is excluded by D15")


# --- inventory ---------------------------------------------------------------------------


def installed_distributions() -> list[Dist]:
    found: dict[str, Dist] = {}
    for dist in distributions():
        meta = dist.metadata
        name = meta.get("Name")
        if not name:
            continue
        licence = licence_from_fields(
            meta.get("License-Expression"), meta.get("License"), meta.get_all("Classifier") or []
        )
        found[canonical_name(name)] = Dist(name=name, version=dist.version, licence=licence)
    return sorted(found.values(), key=lambda d: canonical_name(d.name))


def parse_requirements(path: Path) -> set[str]:
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match:
            names.add(canonical_name(match.group(1)))
    return names


def npm_inventory(lockfile: Path) -> tuple[list[Dist], set[str]]:
    """(every package in an npm v2/v3 lockfile, the keys of the runtime ones).

    Runtime = installed by ``npm ci --omit=dev``: entries without ``dev``/``devOptional``
    (optional platform binaries included, conservatively, whichever platform is built). A name
    that is runtime anywhere in the tree is runtime. Workspace links and the root are skipped.
    """
    data = json.loads(lockfile.read_text(encoding="utf-8"))
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise ValueError(f"{lockfile}: not an npm lockfile v2/v3 (no 'packages')")
    found: dict[tuple[str, str], Dist] = {}
    runtime: set[str] = set()
    for path, meta in packages.items():
        if not path or meta.get("link"):
            continue
        name = meta.get("name") or path.rpartition("node_modules/")[2]
        dist = Dist(
            name=name,
            version=str(meta.get("version", "")),
            licence=str(meta.get("license") or "UNKNOWN"),
            ecosystem=NPM,
        )
        found[(name, dist.version)] = dist
        if not meta.get("dev") and not meta.get("devOptional"):
            runtime.add(dist.key)
    return sorted(found.values(), key=lambda d: (d.key, d.version)), runtime


def load_waivers(path: Path) -> dict[str, str]:
    """Waiver key -> "decision: reason". ``ecosystem = "npm"`` keys an entry ``npm:<name>``."""
    if not path.is_file():
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for w in data.get("waiver", []):
        dist = Dist(name=w["package"], version="", licence="", ecosystem=w.get("ecosystem", PYPI))
        out[dist.key] = f"{w['decision']}: {w['reason']}"
    return out


def evaluate(
    dists: Sequence[Dist],
    runtime: set[str] | None,
    waivers: dict[str, str] | None = None,
) -> Report:
    waivers = {canonical_name(k): v for k, v in (waivers or {}).items()}
    runtime_names = None if runtime is None else {canonical_name(n) for n in runtime}
    entries = []
    for dist in sorted(dists, key=lambda d: (d.ecosystem != PYPI, d.key, d.version)):
        key = dist.key
        if key.startswith(FIRST_PARTY_PREFIX):
            klass = "first-party"
            verdict = Verdict(ALLOW, "workspace package")
        else:
            bundled = runtime_names is None or key in runtime_names
            klass = "bundled" if bundled else "build/ci-only"
            verdict = classify(dist.licence)
        waiver = waivers.get(key) if verdict.status != ALLOW else None
        entries.append(Entry(dist=dist, verdict=verdict, klass=klass, waiver=waiver))
    used = {e.dist.key for e in entries if e.waiver}
    return Report(entries=tuple(entries), unused_waivers=tuple(sorted(set(waivers) - used)))


# --- output ------------------------------------------------------------------------------


def render_markdown(report: Report) -> str:
    lines = [
        "# Sibyl dependency licence inventory",
        "",
        "Generated by `ci/licences.py` (D15). Classes: bundled (gating), build/ci-only (listed),",
        "first-party (workspace). `npm:` rows are the console's packages (package-lock.json).",
        "",
        "| Package | Version | Licence | Class | Verdict | Note |",
        "|---|---|---|---|---|---|",
    ]
    for e in report.entries:
        note = f"waiver {e.waiver}" if e.waiver else e.verdict.reason
        lines.append(
            f"| {e.dist.label} | {e.dist.version} | {e.dist.licence} | {e.klass} "
            f"| {e.verdict.status} | {note} |"
        )
    lines += ["", f"Failures: {len(report.failures)} · Flags: {len(report.flags)}"]
    if report.unused_waivers:
        lines.append(f"Unused waivers: {', '.join(report.unused_waivers)}")
    return "\n".join(lines) + "\n"


def _summary(report: Report) -> str:
    out = [f"licences: {len(report.entries)} packages"]
    out += [f"  FAIL {e.dist.label} {e.dist.licence}: {e.verdict.reason}" for e in report.failures]
    out += [f"  FLAG {e.dist.label} {e.dist.licence}: {e.verdict.reason}" for e in report.flags]
    out += [f"  WAIVED {e.dist.label}: {e.waiver}" for e in report.entries if e.waiver]
    out += [f"  UNUSED WAIVER {w}" for w in report.unused_waivers]
    out.append("licences: FAIL" if report.exit_code else "licences: ok")
    return "\n".join(out)


def _load_inventory(path: Path) -> list[Dist]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    return [Dist(name=r["name"], version=str(r["version"]), licence=r["licence"]) for r in rows]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runtime-requirements", type=Path, help="uv export --no-dev output")
    parser.add_argument("--inventory", type=Path, help="JSON list instead of the live env")
    parser.add_argument(
        "--npm-lock",
        type=Path,
        action="append",
        default=[],
        help="an npm package-lock.json to inventory as well (repeatable)",
    )
    parser.add_argument("--waivers", type=Path, default=DEFAULT_WAIVERS)
    parser.add_argument("--output", type=Path, help="write the markdown inventory here")
    parser.add_argument("--json", type=Path, help="write a JSON inventory here")
    args = parser.parse_args(argv)

    dists = _load_inventory(args.inventory) if args.inventory else installed_distributions()
    runtime = parse_requirements(args.runtime_requirements) if args.runtime_requirements else None
    if args.npm_lock:
        # Without a requirements export every Python package gates (as before); npm packages
        # gate only when they are runtime.
        runtime = {d.key for d in dists} if runtime is None else runtime
        for lock in args.npm_lock:
            npm_dists, npm_runtime = npm_inventory(lock)
            dists = [*dists, *npm_dists]
            runtime |= npm_runtime
    report = evaluate(dists, runtime=runtime, waivers=load_waivers(args.waivers))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(render_markdown(report), encoding="utf-8")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "ecosystem": e.dist.ecosystem,
                "name": e.dist.name,
                "version": e.dist.version,
                "licence": e.dist.licence,
                "class": e.klass,
                "verdict": e.verdict.status,
                "waiver": e.waiver,
            }
            for e in report.entries
        ]
        args.json.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(_summary(report))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
