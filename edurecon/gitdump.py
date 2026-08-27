"""Dump an exposed .git/ directory and reconstruct the source tree.

Given a base like http://host/.git/ and a byte-fetcher, this mirrors the known
git metadata, discovers object SHAs from refs / index / logs, walks loose objects
(zlib + git object format) to pull in every reachable commit/tree/blob, saves a
faithful .git/ copy AND writes the reconstructed working files. Pack files are
saved as-is (a local `git` can use them); loose objects are decoded here.

Bounded (max objects / bytes) so a hostile or huge repo can't run away.
"""
from __future__ import annotations

import os
import re
import zlib

_HEX40 = re.compile(rb"\b([0-9a-f]{40})\b")
MAX_OBJECTS = 4000
MAX_BYTES = 60 * 1024 * 1024

KNOWN = [
    "HEAD", "ORIG_HEAD", "FETCH_HEAD", "config", "description", "packed-refs",
    "index", "COMMIT_EDITMSG", "info/refs", "info/exclude", "logs/HEAD",
    "objects/info/packs", "objects/info/alternates",
    "refs/heads/master", "refs/heads/main", "refs/remotes/origin/HEAD",
    "logs/refs/heads/master", "logs/refs/heads/main",
]


def _safe_join(root: str, rel: str) -> str | None:
    """Join rel under root, refusing traversal/absolute escapes."""
    rel = rel.replace("\\", "/").lstrip("/")
    dest = os.path.realpath(os.path.join(root, rel))
    root = os.path.realpath(root)
    if dest == root or dest.startswith(root + os.sep):
        return dest
    return None


def _write(root: str, rel: str, data: bytes) -> None:
    dest = _safe_join(root, rel)
    if dest is None:
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(data)


def _parse_index_shas(data: bytes) -> set[str]:
    """Pull the 20-byte object SHAs out of a .git/index (DIRC v2/3)."""
    out: set[str] = set()
    if data[:4] != b"DIRC" or len(data) < 12:
        return out
    try:
        ver = int.from_bytes(data[4:8], "big")
        n = int.from_bytes(data[8:12], "big")
    except Exception:
        return out
    if ver not in (2, 3, 4) or n > 100000:
        return out
    i = 12
    for _ in range(n):
        if i + 62 > len(data):
            break
        sha = data[i + 40:i + 60]
        out.add(sha.hex())
        flags = int.from_bytes(data[i + 60:i + 62], "big")
        namelen = flags & 0x0FFF
        entry = 62 + (namelen if namelen < 0x0FFF else 0)
        # entries are padded to a multiple of 8; skip name + padding
        base = i
        i += 62
        # walk to the NUL that terminates the path, then pad
        nul = data.find(b"\x00", i)
        if nul == -1:
            break
        i = nul + 1
        pad = (8 - ((i - base) % 8)) % 8
        i += pad
    return out


def _parse_object(raw: bytes):
    """Decompress a loose object -> (type, content) or (None, None)."""
    try:
        dec = zlib.decompress(raw)
    except zlib.error:
        return None, None
    sp = dec.find(b" ")
    nul = dec.find(b"\x00")
    if sp == -1 or nul == -1 or nul < sp:
        return None, None
    typ = dec[:sp].decode("ascii", "replace")
    return typ, dec[nul + 1:]


def _shas_from_commit(content: bytes) -> set[str]:
    out: set[str] = set()
    for line in content.split(b"\n"):
        if line.startswith(b"tree ") or line.startswith(b"parent "):
            m = _HEX40.search(line)
            if m:
                out.add(m.group(1).decode())
        elif not line:
            break
    return out


def _tree_entries(content: bytes):
    """Yield (mode, name_bytes, hexsha, is_tree) for a tree object."""
    i, n = 0, len(content)
    while i < n:
        sp = content.find(b" ", i)
        if sp == -1:
            break
        mode = content[i:sp]
        nul = content.find(b"\x00", sp)
        if nul == -1 or nul + 21 > n:
            break
        name = content[sp + 1:nul]
        sha = content[nul + 1:nul + 21]
        i = nul + 21
        yield mode, name, sha.hex(), mode.startswith(b"4")


def dump_git(base: str, out_root: str, fetch) -> dict:
    """base -> '.../.git/', out_root -> dump dir, fetch(url)->(bytes|None,err)."""
    if not base.endswith("/"):
        base += "/"
    git_root = os.path.join(out_root, ".git")
    recon_root = os.path.join(out_root, "reconstructed")
    fetched_files = 0
    total = 0
    shas: set[str] = set()

    def grab(rel):
        nonlocal fetched_files, total
        data, err = fetch(base + rel)
        if not data:
            return None
        _write(git_root, rel, data)
        fetched_files += 1
        total += len(data)
        return data

    # 1) known metadata + SHA discovery
    for k in KNOWN:
        data = grab(k)
        if data is None:
            continue
        if k == "index":
            shas |= _parse_index_shas(data)
        else:
            for m in _HEX40.findall(data):
                shas.add(m.decode())

    # 2) packs (saved as-is for a local git to use)
    packs = 0
    packs_txt = grab("objects/info/packs")
    if packs_txt:
        for name in re.findall(rb"pack-[0-9a-f]{40}\.pack", packs_txt):
            nm = name.decode()
            for ext in (".pack", ".idx"):
                fn = nm[:-5] + ext
                if grab("objects/pack/" + fn) is not None:
                    packs += 1

    # 3) BFS loose objects
    store: dict[str, tuple] = {}
    seen: set[str] = set()
    queue = list(shas)
    while queue:
        if len(store) >= MAX_OBJECTS or total >= MAX_BYTES:
            break
        sha = queue.pop()
        if sha in seen or not re.fullmatch(r"[0-9a-f]{40}", sha):
            continue
        seen.add(sha)
        rel = f"objects/{sha[:2]}/{sha[2:]}"
        raw = grab(rel)
        if raw is None:
            continue
        typ, content = _parse_object(raw)
        if typ is None:
            continue
        store[sha] = (typ, content)
        if typ == "commit":
            for s in _shas_from_commit(content):
                if s not in seen:
                    queue.append(s)
        elif typ == "tree":
            for _mode, _name, hexsha, _is_tree in _tree_entries(content):
                if hexsha not in seen:
                    queue.append(hexsha)
        elif typ == "tag":
            m = re.search(rb"object ([0-9a-f]{40})", content)
            if m and m.group(1).decode() not in seen:
                queue.append(m.group(1).decode())

    # 4) reconstruct working tree from every commit's root tree we resolved
    written: list[str] = []

    def walk_tree(sha, prefix):
        node = store.get(sha)
        if not node or node[0] != "tree" or len(written) > MAX_OBJECTS:
            return
        for _mode, name, hexsha, is_tree in _tree_entries(node[1]):
            nm = name.decode("utf-8", "replace")
            rel = (prefix + "/" + nm) if prefix else nm
            if is_tree:
                walk_tree(hexsha, rel)
            else:
                blob = store.get(hexsha)
                if blob and blob[0] == "blob":
                    dest = _safe_join(recon_root, rel)
                    if dest:
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "wb") as fh:
                            fh.write(blob[1])
                        written.append(rel)

    roots = set()
    for sha, (typ, content) in store.items():
        if typ == "commit":
            m = re.search(rb"tree ([0-9a-f]{40})", content)
            if m:
                roots.add(m.group(1).decode())
    for r in roots:
        walk_tree(r, "")

    return {
        "kind": "git",
        "git_files": fetched_files,
        "objects": len(store),
        "packs": packs,
        "files_reconstructed": len(set(written)),
        "sample_files": sorted(set(written))[:40],
        "packed_only": bool(packs and not written),
        "truncated": len(store) >= MAX_OBJECTS or total >= MAX_BYTES,
    }
