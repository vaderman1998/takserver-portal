"""terratak.py with the container engine faked: what an image tarball must look like, how the
settings are checked, the run command, the install / upgrade / refusal paths, the state parsing."""

import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import takcerts  # noqa: E402
import terratak  # noqa: E402

RUNNING = "running\ttrue\tterratak:0.8.3\thealthy\t2026-11-24T10:00:00.123456789Z"


class FakeRun:
    """Answers _run(argv) from (prefix, rc, out) rules (argv[0] reduced to its basename); records calls."""

    def __init__(self, *rules):
        self.rules, self.calls = list(rules), []

    def __call__(self, argv, timeout=60, input_text=None):
        a = [os.path.basename(str(argv[0]))] + [str(x) for x in argv[1:]]
        self.calls.append(a)
        for prefix, rc, out in self.rules:
            if a[:len(prefix)] == list(prefix):
                return rc, out
        return 0, ""

    def ran(self, *prefix):
        return any(c[:len(prefix)] == list(prefix) for c in self.calls)

    def first(self, *prefix):
        return next((c for c in self.calls if c[:len(prefix)] == list(prefix)), None)


def make_image_tar(path, tags=("terratak:0.8.6",), arch="amd64", config_at=None, manifest=True):
    cfg_name = "sha256:abc123"
    with tarfile.open(str(path), "w") as tar:
        def add(name, data):
            b = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(name)
            ti.size = len(b)
            tar.addfile(ti, io.BytesIO(b))
        if manifest:
            add("manifest.json", json.dumps([{"Config": cfg_name, "RepoTags": list(tags), "Layers": ["l1.tar.gz"]}]))
        add(config_at or cfg_name, json.dumps({"architecture": arch, "os": "linux", "created": "2026-11-19T20:25:58.3Z",
                                               "config": {"ExposedPorts": {"8080/tcp": {}}}}))
        add("l1.tar.gz", b"\x1f\x8b" + b"\0" * 30)
    return path


class TerraTAKTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.images = self.tmp / "images"
        self.images.mkdir()
        self.lines = []
        self._orig = (terratak.IMAGE_DIR, terratak.CONFIG_DIR, terratak._run, terratak._stream, terratak.engine,
                      terratak.daemon_ok, terratak.wait_healthy, terratak.host_arch, takcerts.tak_listening)
        terratak.IMAGE_DIR = self.images
        terratak.CONFIG_DIR = self.tmp / "config"
        terratak.engine = lambda: "/usr/bin/docker"
        terratak.daemon_ok = lambda exe: True
        terratak.wait_healthy = lambda port, log, timeout=0: True
        terratak.host_arch = lambda: "amd64"
        takcerts.tak_listening = lambda port=0, host="": False
        self.stream_calls = []
        terratak._stream = lambda argv, log, timeout=0: (self.stream_calls.append(list(argv)) or (0, ["Loaded image: terratak:0.8.6"]))

    def tearDown(self):
        (terratak.IMAGE_DIR, terratak.CONFIG_DIR, terratak._run, terratak._stream, terratak.engine,
         terratak.daemon_ok, terratak.wait_healthy, terratak.host_arch, takcerts.tak_listening) = self._orig
        shutil.rmtree(str(self.tmp), ignore_errors=True)

    def _text(self):
        return "\n".join(self.lines)

    # -- tarballs -------------------------------------------------------------

    def test_inspect_reads_name_version_arch_from_manifest_and_config(self):
        p = make_image_tar(self.images / "terratak-0.8.6-amd64.tar")
        info = terratak.inspect_tar(p)
        self.assertEqual((info["name"], info["version"], info["arch"], info["created"]), ("terratak:0.8.6", "0.8.6", "amd64", "2026-11-19"))
        self.assertEqual(info["size"], p.stat().st_size)
        p2 = make_image_tar(self.images / "oci.tar", arch="arm64", config_at="blobs/sha256/abc123")
        self.assertEqual(terratak.inspect_tar(p2)["arch"], "arm64")

    def test_inspect_refuses_what_is_not_a_terratak_image(self):
        with self.assertRaises(takcerts.CertError) as cm:
            terratak.inspect_tar(make_image_tar(self.images / "other.tar", tags=("nginx:latest",)))
        self.assertIn("nginx:latest", str(cm.exception))
        with self.assertRaises(takcerts.CertError):
            terratak.inspect_tar(make_image_tar(self.images / "nomanifest.tar", manifest=False))
        (self.images / "junk.tar").write_bytes(b"not a tar at all")
        with self.assertRaises(takcerts.CertError):
            terratak.inspect_tar(self.images / "junk.tar")

    def test_list_delete_and_path_checks(self):
        make_image_tar(self.images / "terratak-0.8.6-amd64.tar")
        (self.images / "broken.tar").write_bytes(b"x")
        rows = terratak.list_images()
        self.assertEqual(sorted(r["file"] for r in rows), ["broken.tar", "terratak-0.8.6-amd64.tar"])
        good = next(r for r in rows if r["file"].startswith("terratak"))
        self.assertEqual((good["name"], good["arch"], good["error"]), ("terratak:0.8.6", "amd64", ""))
        self.assertTrue(next(r for r in rows if r["file"] == "broken.tar")["error"])
        for bad in ("../x.tar", "x.tgz", "", "nope.tar"):
            with self.assertRaises(takcerts.CertError):
                terratak.image_path(bad)
        self.assertEqual(terratak.delete_image("broken.tar"), "broken.tar")
        self.assertEqual([r["file"] for r in terratak.list_images()], ["terratak-0.8.6-amd64.tar"])

    # -- settings -------------------------------------------------------------

    def test_settings_validation(self):
        cur = terratak.settings_from({})
        self.assertEqual(cur["port"], 8080)
        s = terratak.validate_settings({"port": "8090", "max_memory": "1g", "t3_memory": "2G", "map_center": "-77.03, 38.89,10",
                                        "auth_user": "ops", "auth_pass": "secret1", "firewall": False}, cur)
        self.assertEqual((s["port"], s["max_memory"], s["t3_memory"], s["map_center"], s["auth_user"], s["auth_pass"], s["firewall"]),
                         (8090, "1G", "2G", "-77.03,38.89,10", "ops", "secret1", False))
        kept = terratak.validate_settings({"auth_user": "ops", "auth_pass": ""}, s)      # blank password keeps the saved one
        self.assertEqual(kept["auth_pass"], "secret1")
        cleared = terratak.validate_settings({"clear_auth": True}, s)
        self.assertEqual((cleared["auth_user"], cleared["auth_pass"]), ("", ""))
        for bad in ({"port": "x"}, {"port": 70000}, {"max_memory": "lots"}, {"map_center": "here"},
                    {"auth_user": "a b"}, {"auth_user": "ops", "auth_pass": "short"}, {"auth_user": "ops"}):
            with self.assertRaises(takcerts.CertError):
                terratak.validate_settings(bad, cur)
        pub = terratak.public_settings(s)
        self.assertNotIn("auth_pass", pub)
        self.assertTrue(pub["auth_set"])
        self.assertEqual(terratak.settings_from({"terratak": {"port": 9000, "junk": 1}})["port"], 9000)

    def test_security_yaml_quotes_and_keeps_health_open(self):
        y = terratak.security_yaml("ad\"min", "p@ss\\word")
        self.assertIn('login: "ad\\"min"', y)
        self.assertIn('password: "p@ss\\\\word"', y)
        self.assertLess(y.index('"/observe/*"'), y.index('"/*"'))
        self.assertIn("authenticate: false", y)

    def test_run_args(self):
        s = dict(terratak.DEFAULTS, port=8090, map_center="1,2")
        a = terratak.run_args("/usr/bin/docker", "terratak:0.8.6", s)
        self.assertEqual(a[:2], ["/usr/bin/docker", "run"])
        self.assertIn("8090:8080", a)
        self.assertIn("terratak-data:/opt/terratak", a)
        self.assertIn("TERRATAK_MAP_CENTER=1,2", a)
        self.assertNotIn("TERRATAK_SERVER_CONFIG_FILES=/config/security.yaml", a)
        self.assertEqual(a[-1], "terratak:0.8.6")
        s.update(auth_user="ops", auth_pass="secret1")
        a = terratak.run_args("/usr/bin/podman", "terratak:0.8.6", s)
        self.assertIn("TERRATAK_SERVER_CONFIG_FILES=/config/security.yaml", a)
        self.assertIn("%s:/config:ro" % terratak.CONFIG_DIR, a)
        self.assertNotIn("secret1", " ".join(a))
        self.assertIn("--label", a)

    # -- install ---------------------------------------------------------------

    def test_fresh_install_loads_runs_and_reports(self):
        make_image_tar(self.images / "terratak-0.8.6-amd64.tar")
        run = FakeRun((["docker", "inspect"], 1, "Error: No such container"), (["docker", "run"], 0, "0123456789abcdef"))
        terratak._run = run
        s = dict(terratak.DEFAULTS, firewall=False)
        r = terratak.install(s, "terratak-0.8.6-amd64.tar", self.lines.append, fqdn="tak.example.com")
        self.assertEqual(self.stream_calls, [["/usr/bin/docker", "load", "-i", str(self.images / "terratak-0.8.6-amd64.tar")]])
        self.assertFalse(run.ran("docker", "rm"))
        self.assertEqual(run.first("docker", "run")[-1], "terratak:0.8.6")
        self.assertEqual(r["url"], "http://tak.example.com:8080/")
        t = self._text()
        self.assertIn("TERRATAK RUNNING", t)
        self.assertIn("no login configured", t)
        self.assertIn("left alone", t)
        self.assertFalse((terratak.CONFIG_DIR / "security.yaml").exists())
        self.assertFalse(takcerts._job_lock.locked())

    def test_upgrade_replaces_the_container_and_writes_the_security_file(self):
        make_image_tar(self.images / "terratak-0.8.6-amd64.tar")
        run = FakeRun((["docker", "inspect"], 0, RUNNING), (["docker", "port"], 0, "0.0.0.0:8080"), (["docker", "run"], 0, "abc"))
        terratak._run = run
        s = dict(terratak.DEFAULTS, auth_user="ops", auth_pass="secret1", firewall=False)
        terratak.install(s, "terratak-0.8.6-amd64.tar", self.lines.append)
        calls = [c[:2] for c in run.calls]
        self.assertLess(calls.index(["docker", "rm"]), calls.index(["docker", "run"]))
        self.assertEqual(run.first("docker", "rm"), ["docker", "rm", "-f", "terratak"])
        self.assertIn("replacing the existing container", self._text())
        y = (terratak.CONFIG_DIR / "security.yaml").read_text()
        self.assertIn('login: "ops"', y)
        self.assertIn("TERRATAK_SERVER_CONFIG_FILES=/config/security.yaml", run.first("docker", "run"))
        self.assertIn("Sign in as 'ops'", self._text())

    def test_install_refuses_wrong_arch_port_in_use_and_load_failure(self):
        make_image_tar(self.images / "terratak-0.8.6-arm64.tar", arch="arm64")
        run = FakeRun((["docker", "inspect"], 1, "no"))
        terratak._run = run
        with self.assertRaises(takcerts.CertError) as cm:
            terratak.install(dict(terratak.DEFAULTS), "terratak-0.8.6-arm64.tar", self.lines.append)
        self.assertIn("arm64", str(cm.exception))
        self.assertEqual(self.stream_calls, [])                        # refused before loading
        make_image_tar(self.images / "terratak-0.8.6-amd64.tar")
        takcerts.tak_listening = lambda port=0, host="": True
        with self.assertRaises(takcerts.CertError) as cm:
            terratak.install(dict(terratak.DEFAULTS), "terratak-0.8.6-amd64.tar", self.lines.append)
        self.assertIn("already in use", str(cm.exception))
        self.assertFalse(run.ran("docker", "run"))
        takcerts.tak_listening = lambda port=0, host="": False
        terratak._stream = lambda argv, log, timeout=0: (1, ["open /x: no such file"])
        with self.assertRaises(takcerts.CertError) as cm:
            terratak.install(dict(terratak.DEFAULTS), "terratak-0.8.6-amd64.tar", self.lines.append)
        self.assertIn("load failed", str(cm.exception))
        self.assertFalse(takcerts._job_lock.locked())

    def test_install_that_never_answers_shows_the_container_log(self):
        make_image_tar(self.images / "terratak-0.8.6-amd64.tar")
        run = FakeRun((["docker", "inspect"], 1, "no"), (["docker", "run"], 0, "abc"), (["docker", "logs"], 0, "boom: java died"))
        terratak._run = run
        terratak.wait_healthy = lambda port, log, timeout=0: False
        with self.assertRaises(takcerts.CertError) as cm:
            terratak.install(dict(terratak.DEFAULTS, firewall=False), "terratak-0.8.6-amd64.tar", self.lines.append)
        self.assertIn("did not answer", str(cm.exception))
        self.assertIn("| boom: java died", self._text())

    def test_install_needs_an_engine(self):
        terratak.engine = lambda: ""
        with self.assertRaises(takcerts.CertError) as cm:
            terratak.install(dict(terratak.DEFAULTS), "x.tar", self.lines.append)
        self.assertIn("Install Docker", str(cm.exception))
        terratak.engine = lambda: "/usr/bin/podman"
        terratak.daemon_ok = lambda exe: False
        with self.assertRaises(takcerts.CertError) as cm:
            terratak.install(dict(terratak.DEFAULTS), "x.tar", self.lines.append)
        self.assertIn("podman", str(cm.exception))

    # -- control, remove, status -------------------------------------------------

    def test_control_and_remove(self):
        run = FakeRun((["docker", "inspect"], 0, RUNNING), (["docker", "port"], 0, "0.0.0.0:8080"))
        terratak._run = run
        st = terratak.control("restart", self.lines.append)
        self.assertTrue(run.ran("docker", "restart", "terratak"))
        self.assertEqual((st["running"], st["health"], st["ports"]), (True, "healthy", "0.0.0.0:8080"))
        with self.assertRaises(takcerts.CertError):
            terratak.control("explode", self.lines.append)
        terratak.remove(self.lines.append, with_data=True)
        self.assertTrue(run.ran("docker", "rm", "-f", "terratak"))
        self.assertTrue(run.ran("docker", "volume", "rm", "terratak-data"))
        self.assertFalse(takcerts._job_lock.locked())
        run2 = FakeRun((["docker", "inspect"], 1, "no"))
        terratak._run = run2
        with self.assertRaises(takcerts.CertError):
            terratak.control("start", self.lines.append)
        terratak.remove(self.lines.append)
        self.assertFalse(run2.ran("docker", "rm"))
        self.assertIn("kept", self._text())

    def test_status_without_engine_and_with_a_running_container(self):
        make_image_tar(self.images / "terratak-0.8.6-amd64.tar")
        terratak.engine = lambda: ""
        st = terratak.status(dict(terratak.DEFAULTS))
        self.assertEqual((st["engine"], st["container"], st["arch"]), ("", None, "amd64"))
        self.assertTrue(st["problems"])
        self.assertEqual(st["files"][0]["name"], "terratak:0.8.6")
        self.assertFalse("auth_pass" in st["settings"])
        terratak.engine = lambda: "/usr/bin/docker"
        terratak._run = FakeRun((["docker", "--version"], 0, "Docker version 27.3.1, build ce12230"),
                                (["docker", "image", "ls"], 0, "terratak:0.8.3\tabc\t1.2GB\nterratak:0.8.6\tdef\t1.2GB"),
                                (["docker", "inspect"], 0, RUNNING), (["docker", "port"], 0, "0.0.0.0:8080"))
        st = terratak.status(dict(terratak.DEFAULTS, port=8080), fqdn="tak.example.com")
        self.assertEqual(st["engine_version"], "Docker version 27.3.1, build ce12230")
        self.assertEqual([i["name"] for i in st["images"]], ["terratak:0.8.3", "terratak:0.8.6"])
        self.assertEqual((st["container"]["image"], st["container"]["started"]), ("terratak:0.8.3", "2026-11-24 10:00:00"))
        self.assertEqual(st["url"], "http://tak.example.com:8080/")
        self.assertEqual(st["problems"], [])


if __name__ == "__main__":
    unittest.main()
