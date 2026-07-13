"""
Materialize the pinned kgcs-spec release into spec/.

Idempotent: always rebuilds spec/ from the tag recorded in SPEC_VERSION, so
local hand-edits to spec/ can never survive. Run this before any validation
or test run (CI must run it unconditionally).

Usage:
    python tools/sync_spec.py [--url URL] [--check]

Options:
    --url URL   Git URL/path of kgcs-spec. Defaults to $KGCS_SPEC_URL,
                falling back to ../kgcs-spec (pre-publication sibling repo;
                the clone happens AT THE TAG, never from a working tree).
    --check     Don't sync; exit 1 if spec/ is missing or does not match
                SPEC_VERSION (fast guard for pre-test hooks).
"""
import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = ROOT / "spec"
PIN_FILE = SPEC_DIR / ".pin"


def _force_rm(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def read_tag() -> str:
    version = (ROOT / "SPEC_VERSION").read_text(encoding="utf-8").strip()
    if not version:
        sys.exit("SPEC_VERSION is empty")
    return f"v{version}"


def check(tag: str) -> int:
    if not PIN_FILE.exists():
        print(f"CHECK FAIL: {PIN_FILE} missing — run `python tools/sync_spec.py`")
        return 1
    pinned = PIN_FILE.read_text(encoding="utf-8").split()
    if not pinned or pinned[0] != tag:
        print(f"CHECK FAIL: spec/ is at {pinned[0] if pinned else '?'} but SPEC_VERSION wants {tag}")
        return 1
    print(f"CHECK OK: spec/ matches {tag} (commit {pinned[1][:12] if len(pinned) > 1 else '?'})")
    return 0


def sync(tag: str, url: str) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="kgcs-spec-"))
    try:
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", "--branch", tag, url, str(tmp / "clone")],
            check=True,
        )
        commit = subprocess.run(
            ["git", "-C", str(tmp / "clone"), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        shutil.rmtree(tmp / "clone" / ".git", onerror=_force_rm)
        if SPEC_DIR.exists():
            shutil.rmtree(SPEC_DIR, onerror=_force_rm)
        shutil.copytree(tmp / "clone", SPEC_DIR)
        PIN_FILE.write_text(f"{tag} {commit}\n", encoding="utf-8")
        print(f"SYNCED: spec/ -> {tag} (commit {commit[:12]}) from {url}")
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"SYNC FAIL: {exc}")
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


GITHUB_SPEC_URL = "https://github.com/Ariadna-KGCS/kgcs-spec.git"


def default_spec_url() -> str:
    """$KGCS_SPEC_URL, else sibling ../kgcs-spec if present, else GitHub."""
    env = os.environ.get("KGCS_SPEC_URL")
    if env:
        return env
    sibling = ROOT.parent / "kgcs-spec"
    return str(sibling) if sibling.is_dir() else GITHUB_SPEC_URL


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=default_spec_url())
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    tag = read_tag()
    return check(tag) if args.check else sync(tag, args.url)


if __name__ == "__main__":
    sys.exit(main())
