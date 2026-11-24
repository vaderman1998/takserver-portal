#!/usr/bin/env python3
"""Self-update of the portal from its git repository: what version runs here, what the
repository has, and the switch itself (fetch, fast-forward, self-tests, restart) with a rollback.

A copied install (files scp'd over, no .git) is adopted on its first update: the folder becomes
a checkout of the repository and keeps uploads/, logs/, backups/ and portal-state.json, which
the repository ignores. Runs as the portal does (root), standard library only, Python 3.6+.
"""

import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

import takcerts

PORTAL_DIR = Path(__file__).resolve().parent
UNIT = "tak-portal"
DEFAULT_REPO = "https://github.com/vaderman1998/takserver-portal.git"
DEFAULT_BRANCH = "main"
BACKUP_KEEP = 5
RESTART_DELAY = 3
# Never in a backup, never touched by an update: the repository ignores them.
LOCAL_ONLY = {".git", "uploads", "logs", "backups", "__pycache__", "portal-state.json"}
# https without credentials in it, git@host:path, or ssh://
REPO_RE = re.compile(r"^(https://[\w.-]+(:\d+)?/[\w./~-]+|git@[\w.-]+:[\w./~-]+|ssh://[\w.@-]+(:\d+)?/[\w./~-]+)$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")

# git asks this for a user name and then a password; the token travels in the environment, never in argv
ASKPASS = """#!/bin/sh
case "$1" in
  *sername*) echo x-access-token ;;
  *) printf '%s\\n' "$PORTAL_GIT_TOKEN" ;;
esac
"""


class UpdateError(takcerts.CertError):
    pass


# ---------------------------------------------------------------------------
# Settings and validation
# ---------------------------------------------------------------------------

def settings_from(state):
    """The update settings out of portal-state.json's dict, with the defaults filled in."""
    return {"repo": (state.get("update_repo") or DEFAULT_REPO).strip(),
            "branch": (state.get("update_branch") or DEFAULT_BRANCH).strip(),
            "token": state.get("update_token") or ""}


def validate_repo(url):
    url = (url or "").strip()
    if not REPO_RE.match(url):
        raise UpdateError("Repository: an https:// URL (no password in it), git@host:path or ssh://. "
                          "A private repository takes a read-only token in the field next to it.")
    return url


def validate_branch(branch):
    branch = (branch or "").strip() or DEFAULT_BRANCH
    if not BRANCH_RE.match(branch) or ".." in branch or branch.endswith("/") or branch.endswith(".lock"):
        raise UpdateError("Branch: letters, numbers, dots, slashes, hyphens and underscores.")
    return branch


def redact(url):
    """A remote URL with any user:password@ cut out, for logs and the dashboard."""
    return re.sub(r"://[^/@]+@", "://***@", url or "")


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------

def _git_bin():
    return shutil.which("git")


def git(args, env=None, timeout=180):
    """Run git in the portal folder; (rc, combined output). Never prompts: a repository that
    wants credentials fails at once instead of hanging the job."""
    exe = _git_bin()
    if not exe:
        return 127, "git is not installed"
    cwd = str(PORTAL_DIR)
    e = dict(os.environ)
    e.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "LANG": "C"})
    if env:
        e.update(env)
    try:
        r = subprocess.run([exe, "-c", "safe.directory=" + cwd, "-c", "advice.detachedHead=false"] + list(args),
                           cwd=cwd, env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout)
        return r.returncode, (r.stdout or "").rstrip()      # rstrip only: porcelain lines start with a space
    except subprocess.TimeoutExpired:
        return 124, "git timed out after %ds" % timeout
    except OSError as exc:
        return 127, str(exc)


def _run(argv, timeout=120, env=None):
    try:
        r = subprocess.run(argv, cwd=str(PORTAL_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout, env=env)
        return r.returncode, r.stdout or ""
    except subprocess.TimeoutExpired:
        return 124, "timed out after %ds" % timeout
    except OSError as exc:
        return 127, str(exc)


def is_clone():
    return (PORTAL_DIR / ".git").exists()


def _need_git():
    if not _git_bin():
        raise UpdateError("git is not installed on this server (apt-get install -y git  /  dnf install -y git).")


class _Auth:
    """GIT_ASKPASS wiring for a token: a throwaway script (mode 700) that answers git's prompts."""

    def __init__(self, token):
        self.env, self.path = {}, None
        if token:
            fd, self.path = tempfile.mkstemp(prefix="portal-askpass-", suffix=".sh")
            with os.fdopen(fd, "w") as f:
                f.write(ASKPASS)
            os.chmod(self.path, 0o700)
            self.env = {"GIT_ASKPASS": self.path, "PORTAL_GIT_TOKEN": token}

    def close(self):
        if self.path:
            takcerts.unlink_quiet(self.path)
            self.path = None


def _hint(out):
    o = out.lower()
    if ("terminal prompts disabled" in o or "authentication failed" in o or "could not read username" in o
            or "repository not found" in o or "permission denied" in o or "invalid username or token" in o):
        return ("The repository did not let this server in: it is private, or the URL is wrong. Save a read-only "
                "token in the Portal card (GitHub: fine-grained token, Contents: read-only), make the repository "
                "public, or give root an SSH deploy key and use the git@github.com: URL.")
    if "could not resolve host" in o or "failed to connect" in o or "network is unreachable" in o or "timed out" in o:
        return "This server cannot reach the repository host (DNS or outbound HTTPS)."
    if "dubious ownership" in o:
        return "The portal folder is owned by another user; run:  chown -R root:root %s" % PORTAL_DIR
    return ""


def _fetch(settings, log):
    auth = _Auth(settings["token"])
    try:
        rc, out = git(["fetch", "--quiet", "origin", settings["branch"]], env=auth.env, timeout=300)
    finally:
        auth.close()
    if rc != 0:
        hint = _hint(out)
        raise UpdateError("git fetch failed: %s%s" % (out.strip()[-400:], ("\n  " + hint) if hint else ""))


def _rev(ref):
    rc, out = git(["rev-parse", "--verify", "--quiet", ref])
    return out.splitlines()[0].strip() if rc == 0 and out else ""


def _origin_url():
    rc, out = git(["remote", "get-url", "origin"])
    return out.splitlines()[0].strip() if rc == 0 and out else ""


def _ensure_origin(settings):
    if not _origin_url():
        rc, out = git(["remote", "add", "origin", settings["repo"]])
        if rc != 0:
            raise UpdateError("git remote add: " + out.strip()[-200:])


def set_remote(url):
    """Point origin at url (a checkout only); the next check or update fetches from there."""
    if not (is_clone() and _git_bin()):
        return False
    rc, out = git(["remote", "set-url", "origin", url]) if _origin_url() else git(["remote", "add", "origin", url])
    if rc != 0:
        raise UpdateError("git remote: " + out.strip()[-200:])
    return True


def _count(range_):
    rc, out = git(["rev-list", "--count", range_])
    try:
        return int(out.splitlines()[0]) if rc == 0 and out else 0
    except ValueError:
        return 0


def _changed_files(a, b):
    rc, out = git(["diff", "--name-only", a, b])
    return [l.strip() for l in out.splitlines() if l.strip()] if rc == 0 else []


def _install_note(changed, log):
    if "install.sh" in changed:
        log("Note: install.sh changed. When convenient, re-run  sudo %s/install.sh  so the service unit picks up "
            "what is new (the running unit keeps working as it is)." % PORTAL_DIR)


def _chmod_scripts():
    for p in PORTAL_DIR.glob("*.sh"):
        try:
            os.chmod(str(p), 0o755)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# What runs here, what the repository has
# ---------------------------------------------------------------------------

def info(settings):
    """What runs here (commit, date, branch, remote, local changes) plus what the card shows."""
    d = {"dir": str(PORTAL_DIR), "git": bool(_git_bin()), "clone": is_clone(), "commit": "", "date": "",
         "subject": "", "branch": "", "remote": "", "dirty": [], "python": sys.executable,
         "repo": redact(settings["repo"]), "wanted_branch": settings["branch"], "token_set": bool(settings["token"])}
    if d["git"] and d["clone"]:
        rc, out = git(["log", "-1", "--date=short", "--format=%h%x09%ad%x09%s"])
        if rc == 0 and out.count("\t") >= 2:
            d["commit"], d["date"], d["subject"] = out.splitlines()[0].split("\t", 2)
        rc, out = git(["rev-parse", "--abbrev-ref", "HEAD"])
        if rc == 0 and out:
            d["branch"] = out.splitlines()[0].strip()
        d["remote"] = redact(_origin_url())
        rc, out = git(["status", "--porcelain", "--untracked-files=no"])
        if rc == 0 and out:                     # "XY path": two status letters, one of them often a space
            d["dirty"] = [l[2:].strip() for l in out.splitlines() if l.strip() and len(l) > 2]
    return d


def check(settings, log):
    """Fetch and say what is new. Changes nothing but the remote-tracking ref."""
    _need_git()
    repo, branch = settings["repo"], settings["branch"]
    if not is_clone():
        log("This install is a copy of the files, not a git checkout (no .git in %s)." % PORTAL_DIR)
        log("Update turns it into a checkout of %s (%s); uploads/, logs/ and portal-state.json stay as they are."
            % (redact(repo), branch))
        return {"clone": False}
    _ensure_origin(settings)
    log("Fetching %s (%s)..." % (redact(_origin_url() or repo), branch))
    _fetch(settings, log)
    old, new = _rev("HEAD"), _rev("origin/" + branch)
    if not new:
        raise UpdateError("origin/%s is not there after the fetch; does that branch exist?" % branch)
    if old == new:
        log("Already up to date at %s." % old[:7])
        return {"clone": True, "behind": 0, "ahead": 0, "commit": old[:7]}
    behind, ahead = _count("HEAD..origin/" + branch), _count("origin/%s..HEAD" % branch)
    log("%d new commit(s) in the repository:" % behind)
    rc, out = git(["log", "--date=short", "--format=  %h %ad %s", "-30", "HEAD..origin/" + branch])
    if rc == 0 and out:
        for line in out.splitlines():
            log(line)
    changed = _changed_files("HEAD", "origin/" + branch)
    if changed:
        log("Files that change (%d): %s%s" % (len(changed), ", ".join(changed[:40]), " ..." if len(changed) > 40 else ""))
    _install_note(changed, log)
    if ahead:
        log("Note: this checkout has %d commit(s) the repository lacks; Update refuses anything but a fast-forward." % ahead)
    return {"clone": True, "behind": behind, "ahead": ahead, "commit": old[:7], "available": new[:7], "changed": changed}


# ---------------------------------------------------------------------------
# Backup, self-tests, restart
# ---------------------------------------------------------------------------

def backup(log=None):
    """Tar the portal's own files (never uploads, logs, state or .git) into backups/portal-<time>.tgz;
    the newest BACKUP_KEEP are kept. The rollback of an adopted copy restores from it."""
    bdir = PORTAL_DIR / "backups"
    bdir.mkdir(mode=0o700, exist_ok=True)
    path = bdir / ("portal-%s.tgz" % time.strftime("%Y%m%d-%H%M%S"))

    def skip_cache(ti):
        return None if "__pycache__" in ti.name or ti.name.endswith(".pyc") else ti
    with tarfile.open(str(path), "w:gz") as tar:
        for child in sorted(PORTAL_DIR.iterdir()):
            if child.name in LOCAL_ONLY:
                continue
            tar.add(str(child), arcname=child.name, filter=skip_cache)
    os.chmod(str(path), 0o600)
    for old in sorted(bdir.glob("portal-*.tgz"))[:-BACKUP_KEEP]:
        takcerts.unlink_quiet(old)
    if log:
        log("  %s" % path)
    return path


def restore_backup(path):
    """Put a backup's files back over the portal folder (local-only names are never in one)."""
    with tarfile.open(str(path), "r:gz") as tar:
        members = [m for m in tar.getmembers()
                   if not (m.name.startswith("/") or m.name.startswith("..") or "/../" in m.name)
                   and m.name.split("/")[0] not in LOCAL_ONLY]
        try:
            tar.extractall(str(PORTAL_DIR), members=members, filter="data")
        except TypeError:                      # a Python without extraction filters
            tar.extractall(str(PORTAL_DIR), members=members)


def run_tests(log, timeout=900):
    """Compile every .py and run the unit tests with the interpreter that runs the portal."""
    py = sys.executable
    files = [str(p) for p in sorted(PORTAL_DIR.glob("*.py"))] + \
            [str(p) for p in sorted((PORTAL_DIR / "tests").glob("*.py"))]
    rc, out = _run([py, "-m", "py_compile"] + files, timeout=120)
    if rc != 0:
        log("  compile: " + out.strip()[-600:])
        return False
    log("  %d files compile" % len(files))
    # The suite builds its own fixtures; an empty TAK_DIR keeps it from reading this box's live
    # CoreConfig (a server certificate named after the host once failed a test that way).
    sandbox = tempfile.mkdtemp(prefix="portal-selftest-")
    env = dict(os.environ, TAK_DIR=os.path.join(sandbox, "tak"), PKI_SNAPSHOT_DIR=os.path.join(sandbox, "snaps"),
               TAK_PORTAL_IMAGES=os.path.join(sandbox, "images"), TERRATAK_CONFIG_DIR=os.path.join(sandbox, "config"))
    try:
        rc, out = _run([py, "-m", "unittest", "discover", "-s", "tests"], timeout=timeout, env=env)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    for line in out.strip().splitlines()[-12:]:
        log("  " + line)
    return rc == 0


def schedule_restart(log, delay=RESTART_DELAY):
    """Restart the portal's own unit in `delay` seconds, from outside this process where possible
    (a transient systemd timer), so the last log lines reach the browser first."""
    if shutil.which("systemd-run"):
        rc, out = _run(["systemd-run", "--quiet", "--on-active=%d" % delay, "--timer-property=AccuracySec=100ms",
                        "systemctl", "restart", UNIT], timeout=30)
        if rc == 0:
            return "systemd timer"
        log("  systemd-run did not take it (%s); using a delayed restart from this process" % out.strip()[-120:])

    def later():
        time.sleep(delay)
        try:
            subprocess.Popen(["systemctl", "--no-block", "restart", UNIT])
        except OSError:
            pass
    threading.Thread(target=later, daemon=True).start()
    return "delayed systemctl"


# ---------------------------------------------------------------------------
# The update
# ---------------------------------------------------------------------------

def _drop_git():
    shutil.rmtree(str(PORTAL_DIR / ".git"), ignore_errors=True)


def _adopt(settings, log):
    """Make this copy a checkout: init, origin, fetch, force the branch over the files."""
    repo, branch = settings["repo"], settings["branch"]
    for args in (["init", "--quiet"], ["remote", "add", "origin", repo]):
        rc, out = git(args)
        if rc != 0:
            raise UpdateError("git %s: %s" % (" ".join(args[:2]), out.strip()[-200:]))
    _fetch(settings, log)
    if not _rev("origin/" + branch):
        raise UpdateError("origin/%s is not there after the fetch; does that branch exist?" % branch)
    rc, out = git(["checkout", "--quiet", "--force", "-B", branch, "origin/" + branch])
    if rc != 0:
        raise UpdateError("git checkout: " + out.strip()[-200:])
    git(["branch", "--quiet", "--set-upstream-to=origin/" + branch, branch])


def _rollback(clone, old, bak, log):
    ok = False
    if clone and old:
        rc, out = git(["reset", "--hard", "--quiet", old])
        ok = rc == 0
        log("  back at %s" % old[:7] if ok else "  git reset failed (%s); restoring the backup" % out.strip()[-120:])
    if not ok:
        if not clone:
            _drop_git()
        restore_backup(bak)
        log("  the previous files are back from %s" % bak)
    _chmod_scripts()


def update(settings, log, restart=True, skip_tests=False):
    """Fetch, fast-forward (or adopt a copied install), run the self-tests, restart the unit.
    A failed self-test rolls back and restarts nothing. Takes the one-job-at-a-time lock."""
    _need_git()
    takcerts._acquire()
    try:
        return _update(settings, log, restart, skip_tests)
    finally:
        takcerts._release()


def _update(settings, log, restart, skip_tests):
    repo, branch = settings["repo"], settings["branch"]
    clone = is_clone()
    log("=== Updating the portal in %s ===" % PORTAL_DIR)
    if clone:
        dirty = info(settings)["dirty"]
        if dirty:
            raise UpdateError("Local changes in %s; the update will not overwrite them. On the server:  cd %s && git stash"
                              "   (or: git checkout -- <file>)" % (", ".join(dirty[:10]), PORTAL_DIR))
        _ensure_origin(settings)
        origin = _origin_url() or repo
    else:
        origin = repo
    log("Step 1/5: Backing up the current files...")
    bak = backup(log)
    old = _rev("HEAD") if clone else ""
    log("Step 2/5: Fetching %s (%s)..." % (redact(origin), branch))
    if clone:
        _fetch(settings, log)
        new = _rev("origin/" + branch)
        if not new:
            raise UpdateError("origin/%s is not there after the fetch; does that branch exist?" % branch)
        if new == old:
            log("Already up to date at %s. Nothing changed; no restart." % old[:7])
            return {"changed": False, "commit": old[:7]}
        changed = _changed_files("HEAD", "origin/" + branch)
        log("  %s -> %s (%d commit(s), %d file(s))" % (old[:7], new[:7], _count("HEAD..origin/" + branch), len(changed)))
        log("Step 3/5: Fast-forwarding...")
        rc, out = git(["merge", "--ff-only", "--quiet", "origin/" + branch])
        if rc != 0:
            raise UpdateError("Fast-forward not possible (%s). Nothing changed." % out.strip()[-200:])
    else:
        log("  (adopting this copy as a checkout; uploads/, logs/ and portal-state.json are kept)")
        try:
            _adopt(settings, log)
        except UpdateError:
            _drop_git()
            raise
        new, changed = _rev("HEAD"), []
        log("Step 3/5: Files now at %s" % new[:7])
    _chmod_scripts()
    log("Step 4/5: Self-tests with %s..." % sys.executable)
    if skip_tests:
        log("  skipped at your request")
    elif not run_tests(log):
        log("  FAILED: rolling back...")
        _rollback(clone, old, bak, log)
        raise UpdateError("The new version failed its self-tests; rolled back to %s and nothing was restarted. "
                          "Backup: %s" % (old[:7] if clone else "the copied files", bak))
    _install_note(changed, log)
    log("Step 5/5: Restart")
    was = old[:7] if clone else "copied files"
    if restart:
        how = schedule_restart(log)
        log("  The portal restarts in %d seconds (%s). This page waits for it, then asks you to sign in again."
            % (RESTART_DELAY, how))
    else:
        log("  Not restarting at your request. The new files run after:  systemctl restart %s" % UNIT)
    log("=== UPDATE COMPLETE: %s -> %s ===" % (was, new[:7]))
    return {"changed": True, "old": was, "new": new[:7], "restart": restart, "backup": str(bak)}
