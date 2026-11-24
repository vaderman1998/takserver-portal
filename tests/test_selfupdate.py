"""selfupdate against a throwaway portal folder: what a backup holds, what info and check report,
and the update's fast-forward, adoption, rollback and refusal paths. git, the self-tests and the
restart are faked; nothing here touches systemd or the network."""

import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import selfupdate  # noqa: E402
import takcerts  # noqa: E402

REPO = "https://github.com/example/takserver-portal.git"
SETTINGS = {"repo": REPO, "branch": "main", "token": ""}
OLD, NEW = "aaaa1111" * 5, "bbbb2222" * 5


class FakeGit:
    """Answers git(args) from (prefix, rc, out) rules, first match wins; records every call."""

    def __init__(self, *rules):
        self.rules, self.calls = list(rules), []

    def __call__(self, args, env=None, timeout=180):
        args = list(args)
        self.calls.append(args)
        for prefix, rc, out in self.rules:
            if args[:len(prefix)] == list(prefix):
                return rc, out
        return 0, ""

    def ran(self, *prefix):
        return any(c[:len(prefix)] == list(prefix) for c in self.calls)


def revs(head, origin):
    return [(["rev-parse", "--verify", "--quiet", "HEAD"], 0, head),
            (["rev-parse", "--verify", "--quiet", "origin/main"], 0, origin)]


class SelfUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        for rel, body in (("app.py", "print(1)\n"), ("takcerts.py", "x = 1\n"), ("install.sh", "#!/bin/sh\n"),
                          ("templates/dashboard.html", "<html>"), ("static/js/app.js", "// js"),
                          ("tests/test_x.py", "pass\n"), ("uploads/pkg.deb", "deb"), ("logs/old.log", "log"),
                          ("portal-state.json", "{}"), ("__pycache__/app.cpython-311.pyc", "pyc"),
                          (".gitignore", "logs/\n")):
            p = self.tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        self.lines, self.marks = [], []
        self._orig = (selfupdate.PORTAL_DIR, selfupdate.git, selfupdate._git_bin,
                      selfupdate.run_tests, selfupdate.schedule_restart)
        selfupdate.PORTAL_DIR = self.tmp
        selfupdate._git_bin = lambda: "/usr/bin/git"
        selfupdate.run_tests = lambda log: (self.marks.append("TESTS") or True)
        selfupdate.schedule_restart = lambda log, delay=3: (self.marks.append("RESTART") or "fake timer")

    def tearDown(self):
        (selfupdate.PORTAL_DIR, selfupdate.git, selfupdate._git_bin,
         selfupdate.run_tests, selfupdate.schedule_restart) = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _clone(self):
        (self.tmp / ".git").mkdir()

    def _text(self):
        return "\n".join(self.lines)

    # -- backup ----------------------------------------------------------------

    def test_backup_holds_the_portals_own_files_only_and_keeps_five(self):
        bdir = self.tmp / "backups"
        bdir.mkdir()
        for i in range(6):
            (bdir / ("portal-2020010%d-000000.tgz" % i)).write_bytes(b"old")
        path = selfupdate.backup(self.lines.append)
        with tarfile.open(str(path)) as tar:
            names = tar.getnames()
        for want in ("app.py", "install.sh", "templates/dashboard.html", "tests/test_x.py", ".gitignore"):
            self.assertIn(want, names)
        for nope in ("uploads", "uploads/pkg.deb", "logs", "logs/old.log", "portal-state.json", "backups"):
            self.assertNotIn(nope, names)
        self.assertFalse([n for n in names if "__pycache__" in n or n.endswith(".pyc")])
        self.assertEqual(len(list(bdir.glob("portal-*.tgz"))), 5)
        self.assertTrue(path.exists())
        self.assertIn(str(path), self._text())

    # -- info ------------------------------------------------------------------

    def test_info_for_a_copied_install(self):
        d = selfupdate.info(SETTINGS)
        self.assertEqual((d["clone"], d["git"], d["commit"], d["repo"], d["token_set"]), (False, True, "", REPO, False))
        self.assertTrue(selfupdate.info(dict(SETTINGS, token="ghp_x"))["token_set"])

    def test_info_for_a_checkout_redacts_the_remote_and_lists_local_changes(self):
        self._clone()
        selfupdate.git = FakeGit((["log"], 0, "e3404f4\t2026-11-23\tfirst commit"),
                                 (["rev-parse", "--abbrev-ref"], 0, "main"),
                                 (["remote", "get-url"], 0, "https://user:tok@github.com/x/y.git"),
                                 (["status"], 0, " M app.py\n M takcerts.py"))
        d = selfupdate.info(SETTINGS)
        self.assertEqual((d["commit"], d["date"], d["subject"], d["branch"]), ("e3404f4", "2026-11-23", "first commit", "main"))
        self.assertEqual(d["remote"], "https://***@github.com/x/y.git")
        self.assertEqual(d["dirty"], ["app.py", "takcerts.py"])
        # the wrapper trims trailing whitespace only, but a first line that lost its leading space must still parse
        selfupdate.git = FakeGit((["status"], 0, "M app.py\n M takcerts.py\nMM both.py\nR  old.py -> new.py"))
        self.assertEqual(selfupdate.info(SETTINGS)["dirty"], ["app.py", "takcerts.py", "both.py", "old.py -> new.py"])

    def test_git_wrapper_keeps_leading_spaces(self):
        class Done:
            returncode, stdout = 0, " M app.py\n M b.py\n\n"
        orig = selfupdate.subprocess.run
        selfupdate.subprocess.run = lambda *a, **k: Done()
        try:
            self.assertEqual(selfupdate.git(["status"]), (0, " M app.py\n M b.py"))
        finally:
            selfupdate.subprocess.run = orig

    # -- check -----------------------------------------------------------------

    def test_check_says_what_is_new(self):
        self._clone()
        g = FakeGit(*revs(OLD, NEW),
                    (["rev-list", "--count", "HEAD..origin/main"], 0, "2"),
                    (["rev-list", "--count", "origin/main..HEAD"], 0, "0"),
                    (["log", "--date=short"], 0, "  bbbb222 2026-11-24 add thing\n  cccc333 2026-11-24 fix thing"),
                    (["diff", "--name-only"], 0, "app.py\ninstall.sh"))
        selfupdate.git = g
        r = selfupdate.check(SETTINGS, self.lines.append)
        self.assertEqual((r["behind"], r["ahead"], r["commit"], r["available"]), (2, 0, OLD[:7], NEW[:7]))
        self.assertTrue(g.ran("fetch", "--quiet", "origin", "main"))
        self.assertTrue(g.ran("remote", "add", "origin", REPO))          # no origin yet: added
        t = self._text()
        self.assertIn("2 new commit(s)", t)
        self.assertIn("add thing", t)
        self.assertIn("install.sh changed", t)

    def test_check_when_current_and_when_copied(self):
        self._clone()
        selfupdate.git = FakeGit(*revs(OLD, OLD))
        self.assertEqual(selfupdate.check(SETTINGS, self.lines.append)["behind"], 0)
        self.assertIn("Already up to date", self._text())
        shutil.rmtree(str(self.tmp / ".git"))
        self.assertEqual(selfupdate.check(SETTINGS, self.lines.append), {"clone": False})
        self.assertIn("not a git checkout", self._text())

    def test_check_explains_a_private_repository(self):
        self._clone()
        selfupdate.git = FakeGit((["fetch"], 128, "fatal: could not read Username for 'https://github.com': terminal prompts disabled"))
        with self.assertRaises(selfupdate.UpdateError) as cm:
            selfupdate.check(SETTINGS, self.lines.append)
        self.assertIn("token", str(cm.exception))

    # -- update ----------------------------------------------------------------

    def test_update_refuses_local_changes_before_touching_anything(self):
        self._clone()
        g = FakeGit((["status"], 0, " M app.py"))
        selfupdate.git = g
        with self.assertRaises(selfupdate.UpdateError) as cm:
            selfupdate.update(SETTINGS, self.lines.append)
        self.assertIn("app.py", str(cm.exception))
        self.assertFalse(g.ran("fetch"))
        self.assertFalse((self.tmp / "backups").exists())
        self.assertFalse(takcerts._job_lock.locked())

    def test_update_fast_forwards_tests_then_restarts(self):
        self._clone()
        g = FakeGit(*revs(OLD, NEW), (["diff", "--name-only"], 0, "app.py"), (["rev-list"], 0, "1"))
        selfupdate.git = g
        r = selfupdate.update(SETTINGS, self.lines.append)
        self.assertEqual((r["changed"], r["old"], r["new"], r["restart"]), (True, OLD[:7], NEW[:7], True))
        self.assertTrue(g.ran("merge", "--ff-only", "--quiet", "origin/main"))
        self.assertEqual(self.marks, ["TESTS", "RESTART"])
        self.assertEqual(len(list((self.tmp / "backups").glob("portal-*.tgz"))), 1)
        self.assertIn("UPDATE COMPLETE", self._text())
        self.assertNotIn("install.sh changed", self._text())
        self.assertFalse(takcerts._job_lock.locked())

    def test_update_without_restart_says_how(self):
        self._clone()
        selfupdate.git = FakeGit(*revs(OLD, NEW))
        selfupdate.update(SETTINGS, self.lines.append, restart=False)
        self.assertEqual(self.marks, ["TESTS"])
        self.assertIn("systemctl restart tak-portal", self._text())

    def test_update_when_already_current_changes_nothing(self):
        self._clone()
        g = FakeGit(*revs(OLD, OLD))
        selfupdate.git = g
        r = selfupdate.update(SETTINGS, self.lines.append)
        self.assertFalse(r["changed"])
        self.assertFalse(g.ran("merge"))
        self.assertEqual(self.marks, [])

    def test_failed_self_tests_roll_a_checkout_back(self):
        self._clone()
        g = FakeGit(*revs(OLD, NEW))
        selfupdate.git = g
        selfupdate.run_tests = lambda log: False
        with self.assertRaises(selfupdate.UpdateError) as cm:
            selfupdate.update(SETTINGS, self.lines.append)
        self.assertIn("rolled back", str(cm.exception))
        self.assertTrue(g.ran("reset", "--hard", "--quiet", OLD))
        self.assertEqual(self.marks, [])
        self.assertFalse(takcerts._job_lock.locked())

    def test_a_copied_install_is_adopted(self):
        g = FakeGit(*revs(NEW, NEW))
        selfupdate.git = g
        r = selfupdate.update(SETTINGS, self.lines.append)
        self.assertEqual((r["changed"], r["old"], r["new"]), (True, "copied files", NEW[:7]))
        self.assertTrue(g.ran("init", "--quiet"))
        self.assertTrue(g.ran("remote", "add", "origin", REPO))
        self.assertTrue(g.ran("fetch", "--quiet", "origin", "main"))
        self.assertTrue(g.ran("checkout", "--quiet", "--force", "-B", "main", "origin/main"))
        self.assertFalse(g.ran("merge"))
        self.assertEqual(self.marks, ["TESTS", "RESTART"])

    def test_a_failed_adoption_leaves_the_copy_as_it_was(self):
        selfupdate.git = FakeGit(*revs(NEW, NEW))

        def tests_that_see_new_files(log):
            (self.tmp / "app.py").write_text("NEW CODE\n")           # what the checkout would have written
            (self.tmp / ".git").mkdir(exist_ok=True)
            return False
        selfupdate.run_tests = tests_that_see_new_files
        with self.assertRaises(selfupdate.UpdateError):
            selfupdate.update(SETTINGS, self.lines.append)
        self.assertEqual((self.tmp / "app.py").read_text(), "print(1)\n")
        self.assertFalse((self.tmp / ".git").exists())
        self.assertEqual((self.tmp / "portal-state.json").read_text(), "{}")
        self.assertEqual(self.marks, [])

    def test_skip_tests_is_honoured(self):
        self._clone()
        selfupdate.git = FakeGit(*revs(OLD, NEW))
        selfupdate.run_tests = lambda log: False
        r = selfupdate.update(SETTINGS, self.lines.append, skip_tests=True)
        self.assertTrue(r["changed"])
        self.assertEqual(self.marks, ["RESTART"])
        self.assertIn("skipped", self._text())

    def test_update_needs_git(self):
        selfupdate._git_bin = lambda: None
        with self.assertRaises(selfupdate.UpdateError):
            selfupdate.update(SETTINGS, self.lines.append)
        self.assertFalse(takcerts._job_lock.locked())

    # -- settings, validation, auth ------------------------------------------

    def test_settings_validation_and_redaction(self):
        self.assertEqual(selfupdate.settings_from({}), {"repo": selfupdate.DEFAULT_REPO, "branch": "main", "token": ""})
        self.assertEqual(selfupdate.settings_from({"update_repo": " x ", "update_branch": "dev", "update_token": "t"}),
                         {"repo": "x", "branch": "dev", "token": "t"})
        for ok in (REPO, "git@github.com:example/takserver-portal.git", "ssh://git@github.com/example/x.git"):
            self.assertEqual(selfupdate.validate_repo(ok), ok)
        for bad in ("https://u:p@github.com/x/y.git", "ftp://x/y", "https://github.com/x/y.git; rm -rf /", "", "x y"):
            with self.assertRaises(takcerts.CertError):
                selfupdate.validate_repo(bad)
        self.assertEqual(selfupdate.validate_branch(""), "main")
        self.assertEqual(selfupdate.validate_branch("release/5.8"), "release/5.8")
        for bad in ("-x", "a..b", "a/", "x.lock", "a b"):
            with self.assertRaises(takcerts.CertError):
                selfupdate.validate_branch(bad)
        self.assertEqual(selfupdate.redact("https://me:secret@github.com/x.git"), "https://***@github.com/x.git")
        self.assertEqual(selfupdate.redact(REPO), REPO)

    def test_askpass_wiring_keeps_the_token_out_of_argv(self):
        a = selfupdate._Auth("ghp_secret")
        try:
            self.assertEqual(a.env["PORTAL_GIT_TOKEN"], "ghp_secret")
            self.assertTrue(os.path.exists(a.env["GIT_ASKPASS"]))
            body = Path(a.env["GIT_ASKPASS"]).read_text()
            self.assertIn("x-access-token", body)
            self.assertNotIn("ghp_secret", body)
        finally:
            a.close()
        self.assertIsNone(a.path)
        self.assertEqual(selfupdate._Auth("").env, {})


if __name__ == "__main__":
    unittest.main()
