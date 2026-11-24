"""Installed-version detection: TAK's two spellings of a release, the war fallback, the cache."""

import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import takcerts  # noqa: E402


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = (takcerts.TAK_DIR, takcerts.package_version)
        takcerts.TAK_DIR = self.tmp
        takcerts._version_cache.update(key=None, at=0.0, value=None)

    def tearDown(self):
        takcerts.TAK_DIR, takcerts.package_version = self._orig
        takcerts._version_cache.update(key=None, at=0.0, value=None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _war(self, shortver, name="takserver.war"):
        p = self.tmp / name
        with zipfile.ZipFile(str(p), "w") as z:
            z.writestr("WEB-INF/classes/ver.json", '{"major": 5, "minor": 4}')
            z.writestr("WEB-INF/classes/shortver.txt", shortver + "\n")
            z.writestr("WEB-INF/lib/deep/er/shortver.txt", "decoy")
        return p

    def test_package_spelling_is_shown_in_taks_own_form(self):
        self.assertEqual(takcerts.normalize_version("5.4-RELEASE106"), "5.4-RELEASE-106")
        self.assertEqual(takcerts.normalize_version("5.4-RELEASE-106"), "5.4-RELEASE-106")
        self.assertEqual(takcerts.normalize_version("5.10-RELEASE3.el8"), "5.10-RELEASE-3.el8")
        self.assertEqual(takcerts.normalize_version("4.8-RELEASE-31-HEAD"), "4.8-RELEASE-31-HEAD")
        self.assertEqual(takcerts.normalize_version(" odd "), "odd")
        self.assertEqual(takcerts.normalize_version(""), "")
        self.assertEqual(takcerts.normalize_version(None), "")

    def test_war_version_reads_shortver_and_tolerates_junk(self):
        self.assertEqual(takcerts.war_version(self._war("5.4-RELEASE-106")), "5.4-RELEASE-106")
        self.assertEqual(takcerts.war_version(self.tmp / "missing.war"), "")
        (self.tmp / "junk.war").write_bytes(b"not a zip")
        self.assertEqual(takcerts.war_version(self.tmp / "junk.war"), "")
        with zipfile.ZipFile(str(self.tmp / "bare.war"), "w") as z:
            z.writestr("WEB-INF/classes/other.txt", "x")
        self.assertEqual(takcerts.war_version(self.tmp / "bare.war"), "")

    def test_the_package_wins_and_the_war_rides_along_as_cross_check(self):
        self._war("5.4-RELEASE-106")
        takcerts.package_version = lambda: ("5.4-RELEASE106", "dpkg:takserver")
        self.assertEqual(takcerts.installed_version(), {
            "version": "5.4-RELEASE-106", "package": "5.4-RELEASE106",
            "source": "dpkg:takserver", "war": "5.4-RELEASE-106"})

    def test_without_a_package_the_war_is_the_answer(self):
        self._war("5.5-RELEASE-88")
        takcerts.package_version = lambda: ("", "")
        v = takcerts.installed_version()
        self.assertEqual((v["version"], v["package"], v["source"], v["war"]),
                         ("5.5-RELEASE-88", "", "war", "5.5-RELEASE-88"))

    def test_nothing_found_is_empty_not_an_error(self):
        takcerts.package_version = lambda: ("", "")
        self.assertEqual(takcerts.installed_version(),
                         {"version": "", "package": "", "source": "", "war": ""})

    def test_cache_is_dropped_when_the_war_changes_or_ages(self):
        calls = []
        takcerts.package_version = lambda: (calls.append(1) or ("5.4-RELEASE106", "rpm:takserver"))
        self._war("5.4-RELEASE-106")
        takcerts.installed_version()
        takcerts.installed_version()
        self.assertEqual(len(calls), 1)
        p = self._war("5.5-RELEASE-88")                       # an install replaced the war
        os.utime(str(p), (time.time() + 5, time.time() + 5))
        self.assertEqual(takcerts.installed_version()["war"], "5.5-RELEASE-88")
        self.assertEqual(len(calls), 2)
        takcerts.installed_version(max_age=0)                # too old: asked again
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
