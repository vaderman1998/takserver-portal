#!/usr/bin/env python3
"""File-level snapshots of everything the certificate jobs touch (certs/ plus the two CoreConfig
files), for boxes without VM snapshots. Same tarball layout and directory as pki-snapshot.sh, so
either tool can restore what the other saved.

A snapshot is /root/tak-pki-snapshots/<name>.tgz (mode 600) holding `CoreConfig.xml`,
`CoreConfig.example.xml` and `certs` relative to /opt/tak. Not saved: TAK's database. Admin
grants made with certmod -A are additive and survive a restore; certificates enrolled by devices
stay in the certificate table either way.
"""

import hashlib
import os
import re
import shutil
import tarfile
import time
from pathlib import Path

import takcerts

SNAP_DIR = Path(os.environ.get("PKI_SNAPSHOT_DIR", "/root/tak-pki-snapshots"))
# CoreConfig first: listing reads it out of the archive, and a gzip stream is read front to back
MEMBERS = ("CoreConfig.xml", "CoreConfig.example.xml", "certs")
AUTO_PREFIX = "auto-"
AUTO_KEEP = 10
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


class SnapshotError(takcerts.CertError):
    pass


def validate_name(name):
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise SnapshotError("Snapshot names: letters, numbers, dots, hyphens and underscores; 80 characters at most.")
    return name


def path_for(name):
    return SNAP_DIR / f"{validate_name(name)}.tgz"


def _tak_dir():
    return Path(takcerts.TAK_DIR)


def _entry(p):
    st = p.stat()
    name = p.name[:-4]
    intermediate = ""
    cc = _member_bytes(p, "CoreConfig.xml")
    if cc:
        ts = os.path.basename(takcerts.coreconfig_tls(cc.decode(errors="replace")).get("truststoreFile", "") or "")
        if ts.startswith("truststore-") and ts.endswith(".jks"):
            intermediate = ts[len("truststore-"):-4]
    return {"name": name, "size": st.st_size, "created": int(st.st_mtime),
            "auto": name.startswith(AUTO_PREFIX), "intermediate": intermediate}


def _member_bytes(tgz, member):
    try:
        with tarfile.open(str(tgz), "r:gz") as tar:      # str(): Python 3.6 tarfile wants a str path
            f = tar.extractfile(member)
            return f.read() if f else None
    except (tarfile.TarError, OSError, KeyError):
        return None


def save(name=None, auto=False):
    """Tar CoreConfig*.xml and certs/ into SNAP_DIR/<name>.tgz. Refuses an existing name.
    `auto` marks a snapshot a job took on its own; only the newest AUTO_KEEP of those are kept."""
    name = validate_name(name or time.strftime("%Y%m%d-%H%M%S"))
    tak = _tak_dir()
    if not (tak / "certs").is_dir():
        raise SnapshotError(f"{tak / 'certs'} not found; nothing to snapshot.")
    try:
        SNAP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(SNAP_DIR, 0o700)
    except OSError as e:
        raise SnapshotError(f"Could not create {SNAP_DIR}: {e}")
    final = SNAP_DIR / f"{name}.tgz"
    if final.exists():
        raise SnapshotError(f"Snapshot '{name}' exists; pick another name.")
    tmp = SNAP_DIR / f".{name}.tmp"
    try:
        with tarfile.open(str(tmp), "w:gz") as tar:
            for m in MEMBERS:
                p = tak / m
                if p.exists():
                    tar.add(str(p), arcname=m)
        os.chmod(tmp, 0o600)
        os.replace(tmp, final)
    except (OSError, tarfile.TarError) as e:
        takcerts.unlink_quiet(tmp)
        raise SnapshotError(f"Could not write {final}: {e}")
    if auto:
        prune_auto()
    return _entry(final)


def prune_auto(keep=AUTO_KEEP):
    """Drop the oldest automatic snapshots beyond `keep`. Named ones are never touched."""
    autos = sorted(SNAP_DIR.glob(f"{AUTO_PREFIX}*.tgz"), key=lambda p: p.stat().st_mtime)
    removed = []
    for p in autos[:-keep] if keep > 0 else autos:
        takcerts.unlink_quiet(p)
        removed.append(p.name[:-4])
    return removed


def list_snapshots():
    if not SNAP_DIR.is_dir():
        return []
    items = [_entry(p) for p in SNAP_DIR.glob("*.tgz") if NAME_RE.match(p.name[:-4])]
    return sorted(items, key=lambda e: (e["created"], e["name"]), reverse=True)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def diff(name):
    """What differs between the snapshot and the live files, by content, within what the snapshot
    holds: {'changed', 'added', 'removed': [paths], 'unchanged': n, 'text': one line per path}."""
    p = path_for(name)
    if not p.exists():
        raise SnapshotError(f"Snapshot '{name}' not found.")
    tak = _tak_dir()
    changed, removed, seen, tops = [], [], set(), set()
    unchanged = 0
    with tarfile.open(str(p), "r:gz") as tar:
        for m in tar:
            tops.add(m.name.split("/")[0])
            if not m.isfile():
                continue
            seen.add(m.name)
            live = tak / m.name
            if not live.is_file():
                removed.append(m.name)
                continue
            f = tar.extractfile(m)
            snap_hash = _sha(f.read()) if f else ""
            try:
                live_hash = _sha(live.read_bytes())
            except OSError:
                live_hash = ""
            if snap_hash == live_hash:
                unchanged += 1
            else:
                changed.append(m.name)
    added = []
    for top in tops:
        base = tak / top
        if base.is_dir():
            for root, _dirs, files in os.walk(base):
                for fn in files:
                    rel = Path(root, fn).relative_to(tak).as_posix()
                    if rel not in seen:
                        added.append(rel)
    out = {"name": name, "changed": sorted(changed), "added": sorted(added), "removed": sorted(removed),
           "unchanged": unchanged}
    lines = [f"{label:8} {it}" for label, items in (("changed", out["changed"]), ("added", out["added"]),
                                                     ("removed", out["removed"])) for it in items]
    if not lines:
        lines.append("no differences")
    lines.append(f"({unchanged} file(s) unchanged)")
    out["text"] = "\n".join(lines)
    return out


def _safe_members(tar):
    """Members that stay inside certs/ and CoreConfig*.xml: a tarball someone edited by hand
    must not be able to write anywhere else."""
    for m in tar:
        name = m.name
        if name.startswith("/") or name.startswith("..") or "/../" in name or "\\" in name or name.endswith("/.."):
            raise SnapshotError(f"Refusing snapshot member '{name}'.")
        if not (m.isfile() or m.isdir() or m.issym()):
            raise SnapshotError(f"Refusing snapshot member '{name}' (special file).")
        if name.split("/")[0] not in MEMBERS:
            raise SnapshotError(f"Refusing snapshot member '{name}' (outside certs/ and CoreConfig*.xml).")
        yield m


def _own_tree(path):
    takcerts.own_tak(path)
    if path.is_dir():
        for root, dirs, files in os.walk(path):
            for n in dirs + files:
                takcerts.own_tak(Path(root, n))


def restore(name, log):
    """Stop TAK Server, replace certs/ and CoreConfig*.xml with the snapshot, start it. The state
    being replaced is saved first as before-restore-<time>."""
    p = path_for(name)
    if not p.exists():
        raise SnapshotError(f"Snapshot '{name}' not found.")
    tak = _tak_dir()
    takcerts._acquire()
    try:
        log(f"=== Restoring snapshot {name} ===")
        with tarfile.open(str(p), "r:gz") as tar:
            tops = sorted({m.name.split("/")[0] for m in _safe_members(tar)})
        if "certs" not in tops:
            raise SnapshotError("That snapshot holds no certs/ directory; nothing to restore.")
        log(f"  Holds: {', '.join(tops)}")
        pre = save(f"before-restore-{time.strftime('%Y%m%d-%H%M%S')}")
        log(f"  The state being replaced is kept as {pre['name']}")
        log("Step 1/3: Stopping TAK Server...")
        rc, out = takcerts._run(["systemctl", "stop", takcerts.TAK_UNIT], timeout=180)
        if rc not in (0, 124):
            raise SnapshotError(f"systemctl stop {takcerts.TAK_UNIT}: {out.strip()[:200]}")
        log("Step 2/3: Putting the files back...")
        certs = tak / "certs"
        if certs.exists():
            shutil.rmtree(str(certs))
        with tarfile.open(str(p), "r:gz") as tar:
            members = list(_safe_members(tar))
            try:
                tar.extractall(str(tak), members=members, filter="data")
            except TypeError:                      # a Python without extraction filters
                tar.extractall(str(tak), members=members)
        for top in tops:
            _own_tree(tak / top)
        log(f"  {', '.join(tops)} restored from {name}")
        log("Step 3/3: Starting TAK Server...")
        takcerts.restart_takserver(log)
        log(f"=== RESTORE COMPLETE: {name} ===")
        return {"name": name, "restored": tops, "kept": pre["name"]}
    finally:
        takcerts._release()


def delete(name):
    p = path_for(name)
    if not p.exists():
        raise SnapshotError(f"Snapshot '{name}' not found.")
    p.unlink()
    return name
