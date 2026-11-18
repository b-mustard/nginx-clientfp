# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""Upstream sources: find the newest release of each series, keep a git clone of it up to date (gs2), export it.

Clones live in extern_src/ and only ever receive shallow tag fetches, so they stay small. Export uses
`git archive`, so extern_src/ is never modified by patching (decision 009).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .model import NGINX_GIT, Flavor, Versions
from .util import REPO, BuildError, log, run

EXTERN = REPO / "extern_src"
NGINX_REPO = EXTERN / "nginx"


def _git(repo: Path, *args: str, capture: bool = False) -> str:
    return run(["git", "-C", repo, *args], capture=capture).stdout or ""


def ensure_repo(path: Path, url: str) -> None:
    """Create the clone if it does not exist (an empty repo with `origin`; tags are fetched on demand)."""
    if (path / ".git").is_dir():
        return
    log(f"cloning {url} -> {path}")
    path.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q", path])
    run(["git", "-C", path, "remote", "add", "origin", url])


def remote_tags(url: str) -> list[str]:
    out = run(["git", "ls-remote", "--tags", "--refs", url], capture=True).stdout
    return [line.split("refs/tags/", 1)[1] for line in out.splitlines() if "refs/tags/" in line]


def local_tags(repo: Path) -> list[str]:
    return _git(repo, "tag", "--list", capture=True).split()


def newest(tags: list[str], pattern: re.Pattern[str]) -> str | None:
    """Highest final release matching pattern (group 1 = patch number); pre-releases never match."""
    best: tuple[int, str] | None = None
    for tag in tags:
        m = pattern.match(tag)
        if m and (best is None or int(m.group(1)) > best[0]):
            best = (int(m.group(1)), tag)
    return best[1] if best else None


def fetch_tag(repo: Path, tag: str) -> None:
    if tag in local_tags(repo):
        return
    log(f"fetching {tag} into {repo}")
    _git(repo, "fetch", "-q", "--depth", "1", "origin", f"refs/tags/{tag}:refs/tags/{tag}")


def _tag_version(tag: str) -> str:
    return tag.split("-", 1)[1]


def resolve(flavor: Flavor, revision: str, *, offline: bool = False, nginx: str | None = None) -> Versions:
    """Pick the nginx version for a flavor (newest upstream unless pinned) and make sure its tag is local."""
    ensure_repo(NGINX_REPO, NGINX_GIT)

    pattern = flavor.nginx_tag_re
    if nginx:
        tag = "release-" + nginx
        if not pattern.match(tag):
            raise BuildError(f"nginx {nginx} is not in the {flavor.name} flavor's series")
    else:
        tags: list[str] = []
        if not offline:
            try:
                tags = remote_tags(NGINX_GIT)
            except BuildError:
                log(f"WARNING: cannot list {NGINX_GIT}; falling back to local tags")
        if not tags:
            tags = local_tags(NGINX_REPO)
        found = newest(tags, pattern)
        if found is None:
            raise BuildError(f"no nginx release matching {pattern.pattern} (offline={offline})")
        tag = found
    if not offline:
        fetch_tag(NGINX_REPO, tag)
    elif tag not in local_tags(NGINX_REPO):
        raise BuildError(f"{tag} is not available locally and --offline was given")

    return Versions(flavor, _tag_version(tag), revision)



def export(repo: Path, tag: str, dest: Path) -> None:
    """Write the tree of `tag` into dest (which must not exist)."""
    if dest.exists():
        raise BuildError(f"{dest} already exists")
    dest.mkdir(parents=True)
    log(f"exporting {repo.name} {tag} -> {dest}")
    archive = subprocess.Popen(["git", "-C", str(repo), "archive", "--format=tar", tag], stdout=subprocess.PIPE)
    assert archive.stdout is not None
    untar = subprocess.run(["tar", "-x", "-C", str(dest)], stdin=archive.stdout, check=False)
    archive.stdout.close()
    if archive.wait() != 0 or untar.returncode != 0:
        raise BuildError(f"exporting {tag} from {repo} failed")
