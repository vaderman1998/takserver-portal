"""snapshots.py against a throwaway /opt/tak: what is saved, what diff reports, what restore puts
back and refuses. systemctl and the TAK restart are faked."""

import io
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import snapshots  # noqa: E402
import takcerts  # noqa: E402

CC = ('<Configuration><security><tls keystoreFile="certs/files/dev.jks" keystorePass="x" '
      'truststoreFile="certs/files/truststore-INT-01.jks" truststorePass="x"/></security></Configuration>')


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tak = self.tmp / "opt" / "tak"
        (self.tak / "certs" / "files").mkdir(parents=True)
        (self.tak / "certs" / "files" / "dev.jks").write_bytes(b"jks-1")
        (self.tak / "certs" / "config.cfg").write_text("cfg")
        (self.tak / "CoreConfig.xml").write_text(CC)
        (self.tak / "CoreConfig.example.xml").write_text(CC)
        (self.tak / "CoreConfig.xsd").write_text("xsd")          # never part of a snapshot
        self.snaps = self.tmp / "snaps"
        self.calls = []
        self._orig = (takcerts.TAK_DIR, snapshots.SNAP_DIR, takcerts._run, takcerts.restart_takserver)
        takcerts.TAK_DIR = self.tak
        snapshots.SNAP_DIR = self.snaps
        takcerts._run = lambda argv, **kw: (self.calls.append(list(argv)) or (0, ""))
        takcerts.restart_takserver = lambda log, **kw: (self.calls.append(["restart"]) or "PEM")

    def tearDown(self):
        takcerts.TAK_DIR, snapshots.SNAP_DIR, takcerts._run, takcerts.restart_takserver = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_holds_exactly_certs_and_the_two_coreconfigs(self):
        e = snapshots.save("before-rotate")
        self.assertEqual(e["name"], "before-rotate")
        self.assertEqual(e["intermediate"], "INT-01")
        self.assertFalse(e["auto"])
        with tarfile.open(str(self.snaps / "before-rotate.tgz")) as tar:
            names = tar.getnames()
        for want in ("certs/files/dev.jks", "certs/config.cfg", "CoreConfig.xml", "CoreConfig.example.xml"):
            self.assertIn(want, names)
        self.assertNotIn("CoreConfig.xsd", names)
        self.assertEqual(names[0], "CoreConfig.xml")
        with self.assertRaises(takcerts.CertError):
            snapshots.save("before-rotate")                   # exists
        for bad in ("../x", "a b", "x/y", "-lead", "x" * 81):
            with self.assertRaises(takcerts.CertError):
                snapshots.save(bad)
        self.assertEqual([x["name"] for x in snapshots.list_snapshots()], ["before-rotate"])
        self.assertEqual(snapshots.list_snapshots()[0]["size"], (self.snaps / "before-rotate.tgz").stat().st_size)
        self.assertRegex(snapshots.save("")["name"], r"^\d{8}-\d{6}$")   # no name: the time

    def test_diff_reports_changed_added_removed_within_what_it_holds(self):
        snapshots.save("base")
        d = snapshots.diff("base")
        self.assertEqual((d["changed"], d["added"], d["removed"]), ([], [], []))
        self.assertEqual(d["unchanged"], 4)
        self.assertIn("no differences", d["text"])
        (self.tak / "certs" / "files" / "dev.jks").write_bytes(b"jks-2")
        (self.tak / "certs" / "files" / "new.pem").write_text("n")
        (self.tak / "certs" / "config.cfg").unlink()
        (self.tak / "CoreConfig.xml").write_text(CC.replace("INT-01", "INT-02"))
        (self.tak / "CoreConfig.xsd").write_text("changed")          # not held: ignored
        d = snapshots.diff("base")
        self.assertEqual(d["changed"], ["CoreConfig.xml", "certs/files/dev.jks"])
        self.assertEqual(d["added"], ["certs/files/new.pem"])
        self.assertEqual(d["removed"], ["certs/config.cfg"])
        self.assertIn("changed  certs/files/dev.jks", d["text"])
        self.assertIn("added    certs/files/new.pem", d["text"])
        with self.assertRaises(takcerts.CertError):
            snapshots.diff("nope")

    def test_restore_puts_the_files_back_and_keeps_the_replaced_state(self):
        snapshots.save("good")
        (self.tak / "certs" / "files" / "dev.jks").write_bytes(b"broken")
        (self.tak / "certs" / "files" / "extra.p12").write_bytes(b"x")
        (self.tak / "CoreConfig.xml").write_text("broken")
        lines = []
        r = snapshots.restore("good", lines.append)
        self.assertEqual((self.tak / "certs" / "files" / "dev.jks").read_bytes(), b"jks-1")
        self.assertFalse((self.tak / "certs" / "files" / "extra.p12").exists())
        self.assertEqual((self.tak / "CoreConfig.xml").read_text(), CC)
        self.assertEqual((self.tak / "CoreConfig.xsd").read_text(), "xsd")
        self.assertEqual(self.calls, [["systemctl", "stop", "takserver"], ["restart"]])
        self.assertEqual(r["restored"], ["CoreConfig.example.xml", "CoreConfig.xml", "certs"])
        self.assertTrue(r["kept"].startswith("before-restore-"))
        self.assertIn(r["kept"], [x["name"] for x in snapshots.list_snapshots()])
        kept = snapshots.diff(r["kept"])                            # it holds the state that was replaced
        self.assertEqual(kept["changed"], ["CoreConfig.xml", "certs/files/dev.jks"])
        self.assertEqual(kept["removed"], ["certs/files/extra.p12"])
        self.assertIn("RESTORE COMPLETE", "\n".join(lines))
        self.assertFalse(takcerts._job_lock.locked())

    def test_restore_refuses_a_tarball_that_escapes_or_misses_certs(self):
        self.snaps.mkdir()

        def tgz(name, member):
            with tarfile.open(str(self.snaps / f"{name}.tgz"), "w:gz") as tar:
                info = tarfile.TarInfo(member)
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
        tgz("evil", "certs/../../etc/passwd")
        tgz("elsewhere", "setenv.sh")
        tgz("nocerts", "CoreConfig.xml")
        for name in ("evil", "elsewhere", "nocerts"):
            with self.assertRaises(takcerts.CertError):
                snapshots.restore(name, lambda line: None)
        self.assertEqual(self.calls, [])                            # refused before TAK Server was stopped
        self.assertEqual((self.tak / "certs" / "files" / "dev.jks").read_bytes(), b"jks-1")
        self.assertFalse(takcerts._job_lock.locked())

    def test_automatic_snapshots_are_pruned_to_the_newest_ten_named_ones_never(self):
        for i in range(12):
            e = snapshots.save(f"auto-before-rotate-{i:02d}", auto=True)
            os.utime(self.snaps / f"{e['name']}.tgz", (1000 + i, 1000 + i))
        snapshots.save("keep-me")
        names = sorted(x["name"] for x in snapshots.list_snapshots())
        self.assertEqual(len([n for n in names if n.startswith("auto-")]), 10)
        self.assertNotIn("auto-before-rotate-00", names)
        self.assertNotIn("auto-before-rotate-01", names)
        self.assertIn("auto-before-rotate-11", names)
        self.assertIn("keep-me", names)
        self.assertTrue(snapshots.list_snapshots()[0]["name"] == "keep-me")   # newest first

    def test_delete(self):
        snapshots.save("x")
        snapshots.delete("x")
        self.assertEqual(snapshots.list_snapshots(), [])
        with self.assertRaises(takcerts.CertError):
            snapshots.delete("x")
        with self.assertRaises(takcerts.CertError):
            snapshots.delete("../x")


if __name__ == "__main__":
    unittest.main()
