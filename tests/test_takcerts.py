"""Unit tests for takcerts.py. Real certificates are made with openssl in a temp dir; everything
that would touch a TAK Server (runuser, keytool, systemctl, psql) is faked."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import takcerts  # noqa: E402

HAVE_OPENSSL = shutil.which("openssl") is not None

CORECONFIG = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Configuration xmlns="http://bbn.com/marti/xml/config">
  <network multicastTTL="5">
    <input _name="stdssl" protocol="tls" port="8089" coreVersion="2" auth="x509"/>
    <connector port="8443" _name="https"/>
    <connector port="8446" clientAuth="false" _name="cert_https"/>
  </network>
  <repository enable="true">
    <connection url="jdbc:postgresql://127.0.0.1:5432/cot" username="martiuser" password="s3cr&amp;t" />
  </repository>
  <security>
    <tls context="TLSv1.2" keymanager="SunX509"
      keystore="JKS" keystoreFile="certs/files/takserver.jks" keystorePass="atakatak"
      truststore="JKS" truststoreFile="certs/files/truststore-INT-01.jks" truststorePass="atakatak"/>
  </security>
  <federation>
    <federation-server port="9000" v2port="9001" v2enabled="true">
      <tls context="TLSv1.2" keystore="JKS" keystoreFile="certs/files/takserver.jks" keystorePass="atakatak"
        truststore="JKS" truststoreFile="certs/files/fed-truststore.jks" truststorePass="fedpass"/>
    </federation-server>
  </federation>
  <certificateSigning CA="TAKServer">
    <certificateConfig><nameEntries><nameEntry name="O" value="Org"/></nameEntries></certificateConfig>
    <TAKServerCAConfig keystore="JKS" keystoreFile="certs/files/INT-01-signing.jks" keystorePass="atakatak"
      validityDays="3650" signatureAlg="SHA256WithRSA"/>
  </certificateSigning>
</Configuration>
"""


def _ssl(*args, cwd=None, input_text=None):
    r = subprocess.run(["openssl"] + list(args), cwd=cwd, input=input_text, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout


class PKI:
    """A root, an intermediate, a second intermediate, a server cert and a couple of leaves."""

    def __init__(self, d):
        self.d = Path(d)
        self.ext = self.d / "ext.cnf"
        # OpenSSL 1.1.1 (RHEL 8) refuses a req config without a distinguished_name section, -subj or not
        self.ext.write_text("[req]\ndistinguished_name = req_dn\n[req_dn]\n"
                            "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,cRLSign,keyCertSign\n"
                            "[leaf]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                            "extendedKeyUsage=clientAuth,serverAuth\n"
                            "[server]\nbasicConstraints=CA:FALSE\nsubjectAltName=DNS:takserver,DNS:tak.example.com,IP:10.0.0.5\n")
        self.ca("ROOT-01", None, days=3650)
        self.ca("INT-01", "ROOT-01")
        self.ca("INT-02", "ROOT-01")

    def _key(self, name):
        p = self.d / f"{name}.key"
        if not p.exists():
            _ssl("genrsa", "-out", str(p), "2048")
        return p

    def ca(self, name, signer, days=730):
        key = self._key(name)
        if signer is None:
            _ssl("req", "-x509", "-new", "-key", str(key), "-days", str(days), "-subj",
                 f"/C=US/ST=State/L=City/O=TAK/OU=Unit/CN={name}", "-out", str(self.d / f"{name}.pem"),
                 "-extensions", "ca", "-config", str(self.ext))
        else:
            self.sign(name, signer, "ca", days)
        return self.d / f"{name}.pem"

    def sign(self, name, signer, section, days=365):
        key = self._key(name)
        csr = self.d / f"{name}.csr"
        _ssl("req", "-new", "-key", str(key), "-subj", f"/C=US/ST=State/L=City/O=TAK/OU=Unit/CN={name}", "-out", str(csr))
        _ssl("x509", "-req", "-in", str(csr), "-CA", str(self.d / f"{signer}.pem"), "-CAkey", str(self.d / f"{signer}.key"),
             "-CAcreateserial", "-days", str(days), "-out", str(self.d / f"{name}.pem"), "-extfile", str(self.ext),
             "-extensions", section)
        return self.d / f"{name}.pem"

    def pem(self, name):
        return (self.d / f"{name}.pem").read_text()


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
class PemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.pki = PKI(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_root_is_self_signed_and_intermediate_is_not(self):
        root = takcerts.pem_info(self.pki.pem("ROOT-01"))
        inter = takcerts.pem_info(self.pki.pem("INT-01"))
        self.assertTrue(root["self_signed"])
        self.assertEqual(root["cn"], "ROOT-01")
        self.assertFalse(inter["self_signed"])
        self.assertEqual(inter["issuer_cn"], "ROOT-01")
        self.assertEqual(inter["issuer"], root["subject"])
        self.assertGreater(inter["days_left"], 700)

    def test_sans_are_normalised(self):
        self.pki.sign("takserver", "INT-01", "server")
        sans = takcerts.cert_sans(self.pki.pem("takserver"))
        self.assertEqual(sans, ["DNS:takserver", "DNS:tak.example.com", "IP:10.0.0.5"])

    def test_first_pem_takes_the_leaf_of_a_chain_file(self):
        chain = self.pki.pem("INT-01") + self.pki.pem("ROOT-01")
        self.assertEqual(takcerts.pem_body(takcerts.first_pem(chain)), takcerts.pem_body(self.pki.pem("INT-01")))

    def test_server_cert_mode_from_files(self):
        d = Path(tempfile.mkdtemp())
        try:
            shutil.copy(self.pki.d / "ROOT-01.pem", d / "root-ca.pem")
            shutil.copy(self.pki.d / "INT-01.pem", d / "ca.pem")
            self.pki.sign("srv-int", "INT-01", "server")
            shutil.copy(self.pki.d / "srv-int.pem", d / "takserver.pem")
            self.assertEqual(takcerts.server_cert_mode(d), "intermediate")
            self.pki.sign("srv-root", "ROOT-01", "server")
            shutil.copy(self.pki.d / "srv-root.pem", d / "takserver.pem")
            self.assertEqual(takcerts.server_cert_mode(d), "root")
            self.pki.sign("srv-old", "INT-02", "server")
            shutil.copy(self.pki.d / "srv-old.pem", d / "takserver.pem")
            self.assertEqual(takcerts.server_cert_mode(d), "unknown")
            (d / "takserver.pem").unlink()
            self.assertEqual(takcerts.server_cert_mode(d), "unknown")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_root_signed_dependents_finds_leaves_signed_by_the_root(self):
        d = Path(tempfile.mkdtemp())
        try:
            shutil.copy(self.pki.d / "ROOT-01.pem", d / "root-ca.pem")
            shutil.copy(self.pki.d / "INT-01.pem", d / "ca.pem")
            self.pki.sign("admin", "INT-01", "leaf")
            self.pki.sign("legacy", "ROOT-01", "leaf")
            for n in ("admin", "legacy"):
                shutil.copy(self.pki.d / f"{n}.pem", d / f"{n}.pem")
                (d / f"{n}.p12").write_bytes(b"x")
            names, n_live = takcerts.root_signed_dependents({"root-01": 2, "int-01": 5}, d)
            self.assertEqual(names, ["legacy"])
            self.assertEqual(n_live, 2)
            self.assertEqual(takcerts.root_signed_dependents(None, d), (["legacy"], None))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_subject_env_falls_back_to_the_root_subject(self):
        d = Path(tempfile.mkdtemp())
        try:
            shutil.copy(self.pki.d / "ROOT-01.pem", d / "root-ca.pem")
            old = takcerts.CERT_METADATA
            takcerts.CERT_METADATA = d / "missing.sh"
            try:
                env = takcerts.subject_env(d)
            finally:
                takcerts.CERT_METADATA = old
            self.assertEqual(env["STATE"], "State")
            self.assertEqual(env["CITY"], "City")
            self.assertEqual(env["ORGANIZATIONAL_UNIT"], "Unit")
            self.assertEqual(env["ORGANIZATION"], "TAK")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class NameTests(unittest.TestCase):
    def test_ca_names(self):
        self.assertEqual(takcerts.validate_ca_name(" INT-CA-02 "), "INT-CA-02")
        for bad in ("INT_CA", "a b", "", "-x", "x" * 65, "é"):
            with self.assertRaises(takcerts.CertError):
                takcerts.validate_ca_name(bad)

    def test_client_names(self):
        self.assertEqual(takcerts.validate_client_name("john_doe@x.org"), "john_doe@x.org")
        for bad in ("ca", "takserver", "truststore-x", "INT-01-signing", "a b", "root-ca"):
            with self.assertRaises(takcerts.CertError):
                takcerts.validate_client_name(bad)

    def test_suggest_next_name(self):
        self.assertEqual(takcerts.suggest_next_name("INT-CA-01"), "INT-CA-02")
        self.assertEqual(takcerts.suggest_next_name("INT-CA-9"), "INT-CA-10")
        self.assertEqual(takcerts.suggest_next_name("MYCA"), "MYCA-02")

    def test_dn_cn(self):
        self.assertEqual(takcerts.dn_cn("CN=jdoe,OU=x,O=y"), "jdoe")
        self.assertEqual(takcerts.dn_cn("OU=x,CN=a\\,b,O=y"), "a,b")
        self.assertEqual(takcerts.dn_cn("no cn here"), "")


class CoreConfigTests(unittest.TestCase):
    def test_tls_and_signing_and_connection_parse(self):
        tls = takcerts.coreconfig_tls(CORECONFIG)
        self.assertTrue(tls["truststoreFile"].endswith("certs/files/truststore-INT-01.jks"))
        self.assertEqual(tls["truststorePass"], "atakatak")
        self.assertTrue(tls["truststoreFile"].startswith(takcerts.TAK_DIR.as_posix() + "/"))
        sig = takcerts.coreconfig_signing(CORECONFIG)
        self.assertTrue(sig["keystoreFile"].endswith("INT-01-signing.jks"))
        self.assertEqual(sig["validityDays"], "3650")
        conn = takcerts.coreconfig_connection(CORECONFIG)
        self.assertEqual(conn["username"], "martiuser")
        self.assertEqual(conn["password"], "s3cr&t")

    def test_point_at_updates_main_tls_and_signing_only(self):
        text, changes = takcerts.coreconfig_point_at(CORECONFIG, "INT-02", cert_pass="newpass", validity_cap=729)
        self.assertIn("truststore", changes)
        self.assertIn("certificateSigning", changes)
        tls = takcerts.coreconfig_tls(text)
        self.assertTrue(tls["truststoreFile"].endswith("truststore-INT-02.jks"))
        self.assertEqual(tls["truststorePass"], "newpass")
        self.assertEqual(tls["keystorePass"], "newpass")
        sig = takcerts.coreconfig_signing(text)
        self.assertTrue(sig["keystoreFile"].endswith("INT-02-signing.jks"))
        self.assertEqual(sig["validityDays"], "729")
        self.assertEqual(sig["keystorePass"], "newpass")
        # federation block untouched
        self.assertIn('truststoreFile="certs/files/fed-truststore.jks" truststorePass="fedpass"', text)
        self.assertEqual(text.count("INT-01"), 0)

    def test_point_at_is_idempotent_and_leaves_short_validity_alone(self):
        text, _ = takcerts.coreconfig_point_at(CORECONFIG, "INT-02", validity_cap=729)
        again, changes = takcerts.coreconfig_point_at(text, "INT-02", validity_cap=729)
        self.assertEqual(again, text)
        self.assertEqual(changes, [])
        short = CORECONFIG.replace('validityDays="3650"', 'validityDays="30"')
        text, changes = takcerts.coreconfig_point_at(short, "INT-01", validity_cap=729)
        self.assertEqual(changes, [])
        self.assertIn('validityDays="30"', text)

    def test_point_at_without_signing_block(self):
        text = CORECONFIG.split("<certificateSigning")[0] + "</Configuration>\n"
        new, changes = takcerts.coreconfig_point_at(text, "INT-02")
        self.assertEqual(changes, ["truststore"])
        self.assertIn("truststore-INT-02.jks", new)

    def test_live_truststore_name(self):
        d = Path(tempfile.mkdtemp())
        try:
            for f in ("truststore-INT-01.jks", "truststore-INT-02.jks", "truststore-root.jks", "fed-truststore.jks"):
                (d / f).write_bytes(b"")
            # CoreConfig names INT-01 -> it wins whatever ca.pem says
            self.assertEqual(takcerts.live_truststore_name(CORECONFIG, d), "truststore-INT-01.jks")
            # CoreConfig names a missing file and ca.pem is unreadable -> several candidates, no guess
            cc = CORECONFIG.replace("truststore-INT-01.jks", "truststore-GONE.jks")
            self.assertEqual(takcerts.live_truststore_name(cc, d), "")
            (d / "truststore-INT-02.jks").unlink()
            self.assertEqual(takcerts.live_truststore_name(cc, d), "truststore-INT-01.jks")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class InventoryTests(unittest.TestCase):
    def test_client_cert_names_skips_ca_material(self):
        d = Path(tempfile.mkdtemp())
        try:
            for f in ("admin.p12", "user.p12", "nodered.p12", "takserver.p12", "INT-01.p12", "INT-01-signing.p12",
                      "INT-02-signing.p12", "truststore-INT-01.p12", "truststore-INT-01.jks", "INT-01.crl",
                      "truststore-INT-02.jks", "truststore-root.p12", "legacy-signing.p12", "root-ca.p12"):
                (d / f).write_bytes(b"")
            names = takcerts.client_cert_names(d)
            self.assertEqual(names, ["admin", "legacy-signing", "nodered", "user"])
            self.assertEqual(takcerts.client_cert_names(d, skip=("nodered",)), ["admin", "legacy-signing", "user"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_downloadable(self):
        for ok in ("admin.p12", "ca.pem", "truststore-INT-01.p12", "user.jks", "INT-01.pem"):
            self.assertTrue(takcerts.downloadable(ok), ok)
        for bad in ("admin.key", "ca-do-not-share.key", "INT-01-signing.p12", "root-ca.pem", "fed-truststore.jks",
                    "INT-01.crl", "../x.p12", "a b.p12", "config.cfg", "makeCert.sh"):
            self.assertFalse(takcerts.downloadable(bad), bad)


class ConfigCfgTests(unittest.TestCase):
    CFG = "[ req ]\ndefault_bits = 2048\n\n[ v3_ca ]\nbasicConstraints=critical,CA:TRUE\n\n[ client ]\nbasicConstraints=critical,CA:FALSE\n\n[ server ]\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage = critical, clientAuth, serverAuth\n"

    def test_block_goes_above_server_section_and_is_replaced_not_duplicated(self):
        names = ["DNS:takserver", "DNS:tak.example.com", "IP:10.0.0.5", "DNS:localhost", "IP:127.0.0.1"]
        out = takcerts.config_cfg_with_names(self.CFG, names)
        self.assertIn(takcerts.SAN_BEGIN, out)
        self.assertLess(out.index("[ alt_names ]"), out.index("[ server ]"))
        self.assertIn("DNS.2 = tak.example.com\n", out)
        self.assertIn("IP.2 = 10.0.0.5\n", out)
        self.assertIn("DNS.3 = localhost\n", out)
        self.assertNotIn("DNS.1", out)  # makeCert writes DNS.1 itself
        again = takcerts.config_cfg_with_names(out, names + ["DNS:other.example.com"])
        self.assertEqual(again.count(takcerts.SAN_BEGIN), 1)
        self.assertIn("DNS.4 = other.example.com\n", again)
        self.assertEqual(again.count("[ server ]"), 1)
        # stripping our block gives the original back
        self.assertEqual(takcerts.config_cfg_with_names(again, ["DNS:takserver"]).replace(
            takcerts.SAN_BEGIN + "\n[ alt_names ]\n" + takcerts.SAN_END + "\n\n", ""), self.CFG)

    def test_no_server_section_means_no_change(self):
        self.assertIsNone(takcerts.config_cfg_with_names("[ req ]\nx=1\n", ["DNS:takserver", "DNS:a"]))

    def test_expected_names_start_with_takserver_and_include_fqdn(self):
        names = takcerts.expected_san_names("TAK.Example.com.", extra=["bad host", "ok.example.net"])
        self.assertEqual(names[0], "DNS:takserver")
        self.assertIn("DNS:tak.example.com", names)
        self.assertIn("DNS:ok.example.net", names)
        self.assertNotIn("DNS:bad host", names)
        self.assertIn("IP:127.0.0.1", names)
        self.assertEqual(len(names), len(set(names)))


class KeytoolParseTests(unittest.TestCase):
    LISTING = ("Keystore type: JKS\nKeystore provider: SUN\n\nYour keystore contains 2 entries\n\n"
               "Alias name: mykey\nCreation date: Jan 1, 2026\nEntry type: trustedCertEntry\n\n"
               "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\n"
               "*******************************************\n\n"
               "Alias name: int-01\nCreation date: Jan 1, 2026\nEntry type: PrivateKeyEntry\nCertificate chain length: 1\n"
               "Certificate[1]:\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")

    def test_parse(self):
        entries = takcerts.parse_keytool_rfc(self.LISTING)
        self.assertEqual([(a, k) for a, k, _p in entries], [("mykey", "trusted"), ("int-01", "key")])
        self.assertEqual(takcerts.pem_body(entries[0][2]), "AAAA")
        self.assertIsNone(takcerts.parse_keytool_rfc("keytool error: java.io.IOException: Keystore was tampered with"))


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
class TrustListDecisionTests(unittest.TestCase):
    """drop_roots / carry_forward / rebuild with a fake keytool: the decisions, not Java."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.pki = PKI(cls.tmp)
        cls.pki.ca("INT-EXPIRED", "ROOT-01", days=1)
        # make INT-EXPIRED really expired: re-sign with a negative-ish window is not possible, so fake it below

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        # the function checks the previous store exists on disk before reading it: real (empty) files
        self.work = Path(tempfile.mkdtemp())
        self.new = str(self.work / "truststore-INT-02.jks")
        self.prev = str(self.work / "truststore-INT-01.jks")
        Path(self.new).write_bytes(b"")
        Path(self.prev).write_bytes(b"")
        self.stores = {}
        self.deleted = []
        self.copied = []
        self.imported = []
        self.log_lines = []
        self._orig = (takcerts.keytool_entries, takcerts.keytool_delete, takcerts.keytool_copy_entry,
                      takcerts.keytool_import_cert, takcerts.keytool_jks_to_p12, takcerts.pem_info)
        takcerts.keytool_entries = lambda path, pw: self.stores.get(str(path))
        takcerts.keytool_delete = self._delete
        takcerts.keytool_copy_entry = self._copy
        takcerts.keytool_import_cert = self._import
        takcerts.keytool_jks_to_p12 = lambda src, dst, pw: (0, "")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)
        (takcerts.keytool_entries, takcerts.keytool_delete, takcerts.keytool_copy_entry,
         takcerts.keytool_import_cert, takcerts.keytool_jks_to_p12, takcerts.pem_info) = self._orig

    def _delete(self, path, pw, alias):
        self.deleted.append(alias)
        self.stores[str(path)] = [e for e in self.stores[str(path)] if e[0] != alias]
        return 0, ""

    def _copy(self, src, srcpass, alias, dst, dstpass, destalias):
        self.copied.append((alias, destalias))
        pem = next(p for a, _k, p in self.stores[str(src)] if a == alias)
        self.stores.setdefault(str(dst), []).append((destalias, "trusted", pem))
        return 0, ""

    def _import(self, path, pw, alias, pem_path, storetype=None):
        self.imported.append((str(path), alias))
        self.stores.setdefault(str(path), []).append((alias, "trusted", Path(pem_path).read_text()))
        return 0, ""

    def log(self, line):
        self.log_lines.append(line)

    def _fed_layout(self):
        files = self.work / "files"
        backup = self.work / "files.before-root-rotate"
        files.mkdir()
        backup.mkdir()
        (files / "fed-truststore.jks").write_bytes(b"fresh")          # what makeRootCa.sh just wrote
        (backup / "fed-truststore.jks").write_bytes(b"previous")
        return files, backup

    def _with_dirs(self, files, fn):
        orig = (takcerts.TAK_DIR, takcerts.FILES_DIR)
        takcerts.TAK_DIR, takcerts.FILES_DIR = self.work, files
        try:
            return fn()
        finally:
            takcerts.TAK_DIR, takcerts.FILES_DIR = orig

    def test_root_rotation_carries_partner_cas_through_the_federation_truststore(self):
        # a partner's root and intermediate live beside our own root in fed-truststore.jks
        self.pki.ca("PARTNER-ROOT", None, days=3650)
        self.pki.ca("PARTNER-INT", "PARTNER-ROOT")
        self.pki.ca("ROOT-02", None, days=3650)
        files, backup = self._fed_layout()
        (files / "root-ca.pem").write_text(self.pki.pem("ROOT-02"))
        cc = ('<Configuration><federation enableFederation="true"><federation-server port="9000">'
              '<tls keystore="JKS" keystoreFile="files/takserver.jks" keystorePass="atakatak" '
              'truststore="JKS" truststoreFile="files/fed-truststore.jks" truststorePass="fedpw"/>'
              '</federation-server></federation></Configuration>')
        entries = [("root-01", "trusted", self.pki.pem("ROOT-01")), ("int-01", "trusted", self.pki.pem("INT-01")),
                   ("partner-root", "trusted", self.pki.pem("PARTNER-ROOT")), ("partner-int", "trusted", self.pki.pem("PARTNER-INT"))]
        new = files / "fed-truststore.jks"
        self.stores[str(backup / "fed-truststore.jks")] = entries
        self.stores[str(new)] = list(entries)                            # the copy the function makes
        self._with_dirs(files, lambda: takcerts.carry_forward_fed_truststore(
            backup, cc, self.pki.pem("ROOT-01"), "ROOT-02", self.log))
        self.assertEqual(new.read_bytes(), b"previous")                 # the old file, with its own password, is back
        self.assertEqual(self.deleted, ["root-01", "int-01"])          # ours went; the partner's self-signed root stayed
        self.assertEqual(self.imported, [(str(new), "root-02")])
        self.assertEqual([a for a, _k, _p in self.stores[str(new)]], ["partner-root", "partner-int", "root-02"])
        self.assertIn("kept 2 partner entries (partner-root, partner-int), dropped root-01, int-01, added ROOT-02",
                      "\n".join(self.log_lines))

    def test_federation_truststore_that_cannot_be_opened_is_left_as_made(self):
        files, backup = self._fed_layout()
        cc = ('<Configuration><federation-server port="9000"><tls keystoreFile="files/takserver.jks" '
              'truststoreFile="files/fed-truststore.jks" truststorePass="wrong"/></federation-server></Configuration>')
        self._with_dirs(files, lambda: takcerts.carry_forward_fed_truststore(
            backup, cc, self.pki.pem("ROOT-01"), "ROOT-02", self.log))
        self.assertEqual((files / "fed-truststore.jks").read_bytes(), b"fresh")
        self.assertEqual(self.deleted, [])
        self.assertEqual(self.imported, [])
        self.assertTrue(any("could not be opened" in line for line in self.log_lines))
        # no federation <tls> at all: nothing happens, nothing logged
        n = len(self.log_lines)
        self._with_dirs(files, lambda: takcerts.carry_forward_fed_truststore(
            backup, "<Configuration/>", self.pki.pem("ROOT-01"), "ROOT-02", self.log))
        self.assertEqual(len(self.log_lines), n)

    def test_drop_roots_removes_only_self_signed_entries(self):
        self.stores["ts"] = [("root-01", "trusted", self.pki.pem("ROOT-01")), ("int-01", "trusted", self.pki.pem("INT-01")),
                             ("int-02", "trusted", self.pki.pem("INT-02"))]
        ok, removed = takcerts.drop_roots("ts", "pw", self.log)
        self.assertTrue(ok)
        self.assertEqual(removed, ["root-01"])
        self.assertEqual([a for a, _k, _p in self.stores["ts"]], ["int-01", "int-02"])

    def test_drop_roots_refuses_a_store_of_only_roots(self):
        self.stores["ts"] = [("mykey", "trusted", self.pki.pem("ROOT-01"))]
        ok, removed = takcerts.drop_roots("ts", "pw", self.log)
        self.assertFalse(ok)
        self.assertEqual(removed, [])
        self.assertEqual(self.deleted, [])
        self.assertTrue(any("trusting nothing" in l for l in self.log_lines))

    def test_drop_roots_unreadable_store_changes_nothing(self):
        ok, removed = takcerts.drop_roots("missing", "pw", self.log)
        self.assertFalse(ok)
        self.assertEqual(self.deleted, [])

    def test_carry_forward_keeps_old_intermediates_never_roots_and_resolves_alias_clashes(self):
        # new store as makeCert.sh ca leaves it: the root under its CN, the new CA under 'mykey'-like alias
        self.stores[self.new] = [("ROOT-01", "trusted", self.pki.pem("ROOT-01")), ("mykey", "trusted", self.pki.pem("INT-02"))]
        # previous live store: root, the CA being replaced (under mykey, the clash), and an older one
        self.pki.ca("INT-00", "ROOT-01")
        self.stores[self.prev] = [("mykey", "trusted", self.pki.pem("INT-01")), ("root-01", "trusted", self.pki.pem("ROOT-01")),
                               ("int-00", "trusted", self.pki.pem("INT-00"))]
        old_pem = self.pki.d / "INT-01.pem"
        trusted = takcerts.carry_forward_truststore(self.new, self.prev, "oldpw", "pw", "INT-01", str(old_pem),
                                                    {"int-00": 3, "int-01": 10}, self.log)
        self.assertIn("int-01", trusted)
        self.assertIn("int-00", trusted)
        self.assertIn("int-02", trusted)
        # root was never copied, INT-01 landed under its CN because 'mykey' clashed
        self.assertEqual(sorted(self.copied), [("int-00", "int-00"), ("mykey", "INT-01")])
        self.assertEqual(self.imported, [])

    def test_carry_forward_adds_the_old_ca_when_the_previous_store_is_unreadable(self):
        self.stores[self.new] = [("ROOT-01", "trusted", self.pki.pem("ROOT-01")), ("INT-02", "trusted", self.pki.pem("INT-02"))]
        old_pem = self.pki.d / "INT-01.pem"
        trusted = takcerts.carry_forward_truststore(self.new, str(self.work / "gone.jks"), "", "pw", "INT-01", str(old_pem), None, self.log)
        self.assertIn("int-01", trusted)
        self.assertEqual(self.imported, [(self.new, "INT-01")])
        self.assertTrue(any("only INT-01 is carried forward" in l for l in self.log_lines))

    def test_carry_forward_drops_an_expired_ca_and_says_who_depends_on_it(self):
        expired = self.pki.pem("INT-EXPIRED")
        real = takcerts.pem_info

        def fake_info(pem):
            info = real(pem)
            if info["cn"] == "INT-EXPIRED":
                info["not_after"] = datetime.utcnow() - timedelta(days=3)
                info["days_left"] = -3
            return info
        takcerts.pem_info = fake_info
        self.stores[self.new] = [("ROOT-01", "trusted", self.pki.pem("ROOT-01")), ("INT-02", "trusted", self.pki.pem("INT-02"))]
        self.stores[self.prev] = [("INT-01", "trusted", self.pki.pem("INT-01")), ("INT-EXPIRED", "trusted", expired)]
        trusted = takcerts.carry_forward_truststore(self.new, self.prev, "pw", "pw", "INT-01", str(self.pki.d / "INT-01.pem"),
                                                    {"int-expired": 4}, self.log)
        self.assertNotIn("int-expired", trusted)
        self.assertTrue(any("Dropped INT-EXPIRED" in l and "4 live client certs" in l for l in self.log_lines))
        self.assertTrue(any("4 live client cert(s) signed by int-expired" in l for l in self.log_lines))

    def test_rebuild_client_truststore_adds_root_to_a_fresh_p12(self):
        d = Path(tempfile.mkdtemp())
        try:
            shutil.copy(self.pki.d / "ROOT-01.pem", d / "root-ca.pem")
            ts = d / "truststore-INT-02.jks"
            ts.write_bytes(b"")
            (d / "truststore-INT-02.p12").write_bytes(b"old")

            def fake_jks_to_p12(src, dst, pw):
                Path(dst).write_bytes(b"new")
                return 0, ""
            takcerts.keytool_jks_to_p12 = fake_jks_to_p12
            self.assertTrue(takcerts.rebuild_client_truststore(ts, "pw", self.log, d))
            self.assertEqual((d / "truststore-INT-02.p12").read_bytes(), b"new")
            self.assertEqual(self.imported, [(str(d / "truststore-INT-02.p12.new"), "root-ca")])
            self.assertFalse((d / "truststore-INT-02.p12.new").exists())
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_rebuild_failure_keeps_the_old_p12(self):
        d = Path(tempfile.mkdtemp())
        try:
            shutil.copy(self.pki.d / "ROOT-01.pem", d / "root-ca.pem")
            ts = d / "truststore-INT-02.jks"
            ts.write_bytes(b"")
            (d / "truststore-INT-02.p12").write_bytes(b"old")
            takcerts.keytool_jks_to_p12 = lambda src, dst, pw: (1, "boom")
            self.assertFalse(takcerts.rebuild_client_truststore(ts, "pw", self.log, d))
            self.assertEqual((d / "truststore-INT-02.p12").read_bytes(), b"old")
            self.assertFalse((d / "truststore-INT-02.p12.new").exists())
        finally:
            shutil.rmtree(d, ignore_errors=True)


class PackageTests(unittest.TestCase):
    def test_enrollment_package(self):
        d = Path(tempfile.mkdtemp())
        try:
            ts = d / "truststore-INT-02.p12"
            ts.write_bytes(b"P12")
            name, data = takcerts.connection_package("tak.example.com", 8089, str(ts), "atakatak")
            self.assertEqual(name, "tak.example.com-dp.zip")
            with zipfile.ZipFile(__import__("io").BytesIO(data)) as z:
                self.assertEqual(sorted(z.namelist()), ["MANIFEST/manifest.xml", "config.pref", "truststore-INT-02.p12"])
                pref = z.read("config.pref").decode()
                man = z.read("MANIFEST/manifest.xml").decode()
            self.assertIn("tak.example.com:8089:ssl", pref)
            self.assertIn('key="caLocation0" class="class java.lang.String">cert/truststore-INT-02.p12', pref)
            self.assertIn('enrollForCertificateWithTrust0" class="class java.lang.Boolean">true', pref)
            self.assertNotIn("certificateLocation0", pref)
            self.assertIn('zipEntry="truststore-INT-02.p12"', man)
            self.assertIn('name="onReceiveDelete" value="true"', man)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_full_package_with_client_cert_disables_enrollment(self):
        d = Path(tempfile.mkdtemp())
        try:
            ts = d / "truststore-INT-02.p12"
            ts.write_bytes(b"P12")
            cl = d / "jdoe.p12"
            cl.write_bytes(b"CL")
            name, data = takcerts.connection_package("tak.example.com", 8089, str(ts), "atakatak", str(cl), "clpass", "Prod")
            self.assertEqual(name, "tak.example.com-jdoe-dp.zip")
            with zipfile.ZipFile(__import__("io").BytesIO(data)) as z:
                pref = z.read("config.pref").decode()
                self.assertIn("jdoe.p12", z.namelist())
            self.assertIn('certificateLocation0" class="class java.lang.String">cert/jdoe.p12', pref)
            self.assertIn('clientPassword0" class="class java.lang.String">clpass', pref)
            self.assertIn('description0" class="class java.lang.String">Prod', pref)
            self.assertNotIn("enrollForCertificateWithTrust0", pref)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ScriptCopyTests(unittest.TestCase):
    def test_days_override_touches_only_the_signing_line(self):
        d = Path(tempfile.mkdtemp())
        try:
            script = d / "makeCert.sh"
            script.write_text('default_crl_days= 730\nopenssl x509 $PROVIDER_OPTS -sha256 -req -days 730 -in "${SNAME}".csr -CA ca.pem\n')
            old_certs = takcerts.CERTS_DIR
            takcerts.CERTS_DIR = d
            try:
                tmp = takcerts._script_with_days(script, 400, "ca")
                text = tmp.read_text()
            finally:
                takcerts.CERTS_DIR = old_certs
            self.assertIn("-req -days 400 ", text)
            self.assertIn("default_crl_days= 730", text)
            root = d / "makeRootCa.sh"
            root.write_text("openssl req -new -x509 -sha256 -days 3652 -extensions v3_ca\n")
            takcerts.CERTS_DIR = d
            try:
                tmp = takcerts._script_with_days(root, 1826, "root")
                self.assertIn("-days 1826 ", tmp.read_text())
            finally:
                takcerts.CERTS_DIR = old_certs
        finally:
            shutil.rmtree(d, ignore_errors=True)


class MetadataTests(unittest.TestCase):
    def test_literals_and_password_rewrite(self):
        d = Path(tempfile.mkdtemp())
        try:
            meta = d / "cert-metadata.sh"
            meta.write_text('COUNTRY=US\nSTATE=${STATE}\nCITY=Denver\nORGANIZATION=${ORGANIZATION:-TAK}\n'
                            'ORGANIZATIONAL_UNIT="Ops Unit"\n\nCAPASS=hardpass\nPASS=${PASS:-$CAPASS}\nDIR=files\n')
            old = takcerts.CERT_METADATA
            takcerts.CERT_METADATA = meta
            try:
                lit = takcerts._metadata_literals()
                self.assertEqual(lit["CITY"], "Denver")
                self.assertEqual(lit["ORGANIZATIONAL_UNIT"], "Ops Unit")
                self.assertEqual(lit["CAPASS"], "hardpass")
                self.assertNotIn("STATE", lit)
                self.assertTrue(takcerts.set_metadata_password("newpass"))
                text = meta.read_text()
                self.assertIn('CAPASS="newpass"', text)
                self.assertIn("PASS=${PASS:-$CAPASS}", text)   # templated line untouched
            finally:
                takcerts.CERT_METADATA = old
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
