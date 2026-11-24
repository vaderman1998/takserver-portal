"""The layout myTeckNet's installTAK leaves behind: the server certificate named after the host,
a <crl> per intermediate inside <security><tls>, CAkey/CAcertificate on TAKServerCAConfig, a
${CAPASS:-...} default in cert-metadata.sh, and a <host>-le.jks keystore for Let's Encrypt."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import takcerts  # noqa: E402

CC = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Configuration xmlns="http://bbn.com/marti/xml/config">
  <network multicastTTL="5">
    <input _name="stdssl" protocol="tls" port="8089" coreVersion="2"/>
    <connector port="8443" _name="https"/>
    <connector port="8446" clientAuth="false" _name="cert_https_LE"  keystore="JKS" keystoreFile="certs/files/takhost01-le.jks" keystorePass="atakatak"/>
  </network>
  <auth x509groups="true" x509groupsDefaultRDN="true" x509addAnonymous="false" x509useGroupCache="true" x509checkRevocation="true">
    <File location="UserAuthenticationFile.xml"/>
  </auth>
  <security>
    <tls context="TLSv1.2"
      keymanager="SunX509"
      keystore="JKS" keystoreFile="certs/files/takhost01.jks" keystorePass="atakatak"
      truststore="JKS" truststoreFile="certs/files/truststore-TAK-ID-CA-01.jks" truststorePass="atakatak">
    <crl _name="TAKServer CA" crlFile="certs/files/TAK-ID-CA-01.crl"/>
    </tls>
  </security>
  <federation enableFederation="true">
    <federation-server port="9000" v2port="9001" v2enabled="true">
      <tls context="TLSv1.2" keystore="JKS" keystoreFile="certs/files/takhost01.jks" keystorePass="atakatak"
        truststore="JKS" truststoreFile="certs/files/fed-truststore.jks" truststorePass="atakatak"/>
    </federation-server>
  </federation>
  <certificateSigning CA="TAKServer">
    <certificateConfig><nameEntries><nameEntry name="O" value="Org"/><nameEntry name="OU" value="Unit"/></nameEntries></certificateConfig>
    <TAKServerCAConfig keystore="JKS" keystoreFile="certs/files/TAK-ID-CA-01-signing.jks" keystorePass="atakatak" validityDays="30" signatureAlg="SHA256WithRSA" CAkey="/opt/tak/certs/files/TAK-ID-CA-01" CAcertificate="/opt/tak/certs/files/TAK-ID-CA-01" />
  </certificateSigning>
</Configuration>
"""


class ServerNameTests(unittest.TestCase):
    def test_server_name_follows_the_keystore(self):
        self.assertEqual(takcerts.server_cert_name(CC), "takhost01")
        docs = CC.replace("takhost01.jks", "takserver.jks")
        self.assertEqual(takcerts.server_cert_name(docs), "takserver")
        self.assertEqual(takcerts.server_cert_name("<Configuration/>"), "takserver")

    def test_server_cert_and_le_keystore_are_never_client_certs(self):
        d = Path(tempfile.mkdtemp())
        try:
            for f in ("webadmin.p12", "takhost01.p12", "takhost01-le.p12", "takhost01-le.jks", "user.p12",
                      "TAK-ID-CA-01-signing.p12", "truststore-TAK-ID-CA-01.jks", "TAK-ID-CA-01.crl"):
                (d / f).write_bytes(b"")
            self.assertEqual(takcerts.client_cert_names(d, server_name="takhost01"), ["user", "webadmin"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_san_block_skips_the_name_makecert_writes_itself(self):
        names = takcerts.expected_san_names("tak.example.com", server_name="takhost01")
        self.assertEqual(names[0], "DNS:takhost01")
        cfg = "[ req ]\nx=1\n\n[ server ]\nbasicConstraints=critical,CA:FALSE\n"
        out = takcerts.config_cfg_with_names(cfg, ["DNS:takhost01", "DNS:tak.example.com"], "takhost01")
        self.assertIn("DNS.2 = tak.example.com\n", out)
        self.assertNotIn("takhost01", out)

    def test_downloads_never_hand_out_the_server_or_le_keystore(self):
        for bad in ("takhost01.jks", "takhost01.p12", "takhost01-le.jks", "takhost01-le.p12", "takserver.jks"):
            self.assertFalse(takcerts.downloadable(bad, "takhost01"), bad)
        for ok in ("takhost01.pem", "webadmin.p12", "truststore-TAK-ID-CA-02.p12", "ca.pem"):
            self.assertTrue(takcerts.downloadable(ok, "takhost01"), ok)


class CoreConfigInstallTakTests(unittest.TestCase):
    def test_rotation_adds_a_crl_for_the_new_ca_and_moves_cakey_and_cacertificate(self):
        text, changes = takcerts.coreconfig_point_at(CC, "TAK-ID-CA-02", validity_cap=729)
        self.assertEqual(sorted(changes), ["certificateSigning", "crl", "truststore"])
        tls = takcerts.coreconfig_tls(text)
        self.assertTrue(tls["truststoreFile"].endswith("truststore-TAK-ID-CA-02.jks"))
        self.assertTrue(tls["keystoreFile"].endswith("takhost01.jks"))   # the server keystore is left alone
        self.assertIn('crlFile="certs/files/TAK-ID-CA-01.crl"', text)   # the old CA is still trusted: keep its CRL
        self.assertIn('crlFile="certs/files/TAK-ID-CA-02.crl"', text)
        self.assertLess(text.index("TAK-ID-CA-01.crl"), text.index("TAK-ID-CA-02.crl"))
        self.assertIn('CAkey="/opt/tak/certs/files/TAK-ID-CA-02"', text)
        self.assertIn('CAcertificate="/opt/tak/certs/files/TAK-ID-CA-02"', text)
        self.assertIn('keystoreFile="certs/files/TAK-ID-CA-02-signing.jks"', text)
        self.assertIn('validityDays="30"', text)                        # 30 < cap: untouched
        self.assertIn('truststoreFile="certs/files/fed-truststore.jks"', text)
        # the 8446 Let's Encrypt connector and the <auth> attributes are untouched
        self.assertIn('keystoreFile="certs/files/takhost01-le.jks"', text)
        self.assertIn('x509checkRevocation="true"', text)
        # idempotent
        again, changes2 = takcerts.coreconfig_point_at(text, "TAK-ID-CA-02", validity_cap=729)
        self.assertEqual(again, text)
        self.assertEqual(changes2, [])
        self.assertEqual(again.count("<crl"), 2)

    def test_no_crl_entries_means_none_are_added(self):
        plain = CC.replace('    <crl _name="TAKServer CA" crlFile="certs/files/TAK-ID-CA-01.crl"/>\n', "")
        text, changes = takcerts.coreconfig_point_at(plain, "TAK-ID-CA-02")
        self.assertNotIn("crl", changes)
        self.assertNotIn("<crl", text)

    def test_revoke_drops_only_that_cas_crl(self):
        text, _ = takcerts.coreconfig_point_at(CC, "TAK-ID-CA-02")
        text, removed = takcerts.coreconfig_drop_crl(text, "TAK-ID-CA-01")
        self.assertTrue(removed)
        self.assertNotIn("TAK-ID-CA-01.crl", text)
        self.assertIn("TAK-ID-CA-02.crl", text)
        self.assertIn("</tls>", text)
        text2, removed2 = takcerts.coreconfig_drop_crl(text, "TAK-ID-CA-01")
        self.assertFalse(removed2)
        self.assertEqual(text2, text)


class MetadataDefaultTests(unittest.TestCase):
    def test_capass_default_counts_and_is_rewritten_in_place(self):
        d = Path(tempfile.mkdtemp())
        try:
            meta = d / "cert-metadata.sh"
            meta.write_text("COUNTRY='US'\nSTATE='Texas'\nCITY='Austin'\nORGANIZATION='TAK'\nORGANIZATIONAL_UNIT='Ops'\n\n"
                            "CAPASS=${CAPASS:-hardpass}\nPASS=${PASS:-$CAPASS}\nDIR=files\n")
            old = takcerts.CERT_METADATA
            takcerts.CERT_METADATA = meta
            try:
                lit = takcerts._metadata_literals()
                self.assertEqual(lit["CAPASS"], "hardpass")
                self.assertEqual(lit["STATE"], "Texas")
                self.assertNotIn("PASS", lit)
                self.assertTrue(takcerts.set_metadata_password("newpass"))
                text = meta.read_text()
                self.assertIn("CAPASS=${CAPASS:-newpass}\n", text)
                self.assertIn("PASS=${PASS:-$CAPASS}\n", text)
                self.assertEqual(takcerts._metadata_literals()["CAPASS"], "newpass")
            finally:
                takcerts.CERT_METADATA = old
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class ConnectorTests(unittest.TestCase):
    def test_connectors_are_listed_and_a_missing_le_keystore_is_dangling(self):
        conns = takcerts.coreconfig_connectors(CC)
        ports = {c["port"]: c for c in conns}
        self.assertEqual(ports["8443"]["keystoreFile"], "")
        self.assertTrue(ports["8446"]["keystoreFile"].endswith("certs/files/takhost01-le.jks"))
        self.assertFalse(ports["8446"]["exists"])
        self.assertEqual(ports["8446"]["name"], "cert_https_LE")

    def test_reset_puts_8446_back_on_taks_certificate_and_keeps_other_attributes(self):
        text = CC.replace('_name="cert_https_LE"  keystore', 'enableWebtak="true" _name="cert_https_LE"  keystore')
        new, changed = takcerts.coreconfig_reset_connector(text, "8446")
        self.assertTrue(changed)
        self.assertIn('<connector port="8446" clientAuth="false" enableWebtak="true" _name="cert_https"/>', new)
        self.assertNotIn("takhost01-le.jks", new)
        self.assertEqual(new.count("<connector"), 2)
        again, changed2 = takcerts.coreconfig_reset_connector(new, "8446")
        self.assertFalse(changed2)
        self.assertEqual(again, new)
        self.assertEqual([c for c in takcerts.coreconfig_connectors(new) if c["keystoreFile"]], [])


class FederationTests(unittest.TestCase):
    """installTAK enables federation with a <tls> that serves the same server keystore as
    <security><tls> and a fed-truststore.jks of its own."""

    def test_federation_tls_is_read_from_its_own_block(self):
        fed = takcerts.coreconfig_federation_tls(CC)
        self.assertTrue(fed["keystoreFile"].endswith("certs/files/takhost01.jks"))
        self.assertTrue(fed["truststoreFile"].endswith("certs/files/fed-truststore.jks"))
        self.assertEqual(fed["truststorePass"], "atakatak")
        self.assertTrue(takcerts.federation_enabled(CC))
        self.assertFalse(takcerts.federation_enabled(CC.replace('enableFederation="true"', 'enableFederation="false"')))
        self.assertEqual(takcerts.coreconfig_federation_tls("<Configuration/>")["keystoreFile"], "")

    def test_password_change_follows_into_federation_keystore_only(self):
        text, changes = takcerts.coreconfig_point_at(CC, "TAK-ID-CA-02", cert_pass="newpw")
        self.assertIn("federation keystorePass", changes)
        fed = takcerts.coreconfig_federation_tls(text)
        self.assertEqual(fed["keystorePass"], "newpw")           # same takhost01.jks, reissued with the new password
        self.assertEqual(fed["truststorePass"], "atakatak")      # fed-truststore.jks is untouched by a rotation
        self.assertEqual(takcerts.coreconfig_tls(text)["keystorePass"], "newpw")
        self.assertEqual(takcerts.coreconfig_tls(text)["truststorePass"], "newpw")
        self.assertIn('keystoreFile="certs/files/takhost01-le.jks" keystorePass="atakatak"', text)   # 8446 LE untouched
        again, changes2 = takcerts.coreconfig_point_at(text, "TAK-ID-CA-02", cert_pass="newpw")
        self.assertEqual(changes2, [])
        self.assertEqual(again, text)

    def test_a_separate_federation_keystore_keeps_its_password(self):
        cc = CC.replace('<tls context="TLSv1.2" keystore="JKS" keystoreFile="certs/files/takhost01.jks" keystorePass="atakatak"\n        truststore="JKS" truststoreFile="certs/files/fed-truststore.jks"',
                        '<tls context="TLSv1.2" keystore="JKS" keystoreFile="certs/files/fed-server.jks" keystorePass="fedonly"\n        truststore="JKS" truststoreFile="certs/files/fed-truststore.jks"')
        self.assertTrue(takcerts.coreconfig_federation_tls(cc)["keystoreFile"].endswith("fed-server.jks"))
        text, changes = takcerts.coreconfig_point_at(cc, "TAK-ID-CA-02", cert_pass="newpw")
        self.assertNotIn("federation keystorePass", changes)
        self.assertEqual(takcerts.coreconfig_federation_tls(text)["keystorePass"], "fedonly")

    def test_no_password_change_leaves_federation_alone(self):
        text, changes = takcerts.coreconfig_point_at(CC, "TAK-ID-CA-02")
        self.assertNotIn("federation keystorePass", changes)
        self.assertEqual(takcerts.coreconfig_federation_tls(text), takcerts.coreconfig_federation_tls(CC))
