#!/usr/bin/env python3
"""takcerts.py - TAK Server certificate authority operations for the TAK Server Portal.

Native (.deb / .rpm) TAK Server installs only: /opt/tak, the `tak` system user and the
systemd unit `takserver`. Everything goes through TAK's own scripts (makeRootCa.sh,
makeCert.sh) and the Java keytool, exactly as an operator would by hand. Standard library only.

How TAK's PKI is laid out (this is what every operation below relies on):

  files/root-ca.pem + root-ca-do-not-share.key          the root CA
  files/ca.pem + ca-do-not-share.key + ca-trusted.pem   the WORKING slot: whatever sits here signs
                                                         the next makeCert.sh run
  files/<INT>.pem, <INT>-signing.jks, truststore-<INT>.jks  one set per intermediate ever made
  CoreConfig <security><tls truststoreFile=...>         what TAK Server trusts on 8089 / 8443
  CoreConfig <TAKServerCAConfig keystoreFile=...>       what signs certificates enrolled on 8446

Why the server certificate's signer matters: ATAK / iTAK / WinTAK trust the CA they enrolled
with and ignore the chain the server sends. A server certificate signed by the intermediate
therefore drops every device the moment that intermediate is rotated; one signed by the root
keeps them connected while users move to the new intermediate.
"""

import glob
import io
import json
import os
import posixpath
import re
try:
    import pwd
except ImportError:  # Windows, for the unit tests only
    pwd = None
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

TAK_DIR = Path(os.environ.get("TAK_DIR", "/opt/tak"))
CERTS_DIR = TAK_DIR / "certs"
FILES_DIR = CERTS_DIR / "files"
CORECONFIG = TAK_DIR / "CoreConfig.xml"
CERT_METADATA = CERTS_DIR / "cert-metadata.sh"
CONFIG_CFG = CERTS_DIR / "config.cfg"
TAK_USER = os.environ.get("TAK_USER", "tak")
TAK_UNIT = "takserver"

DEFAULT_CERT_PASSWORD = "atakatak"
SERVER_CERT_NAME = "takserver"       # the TAK docs' name; installTAK uses the host name (server_cert_name())
USERMANAGER_JAR = TAK_DIR / "utils" / "UserManager.jar"
ADMIN_CERT_NAMES = ("webadmin", "admin")   # installTAK's and the TAK docs' admin certificate names
SIGNERS = ("root", "intermediate")
INTERMEDIATE_DEFAULT_DAYS = 730      # what makeCert.sh ca hard-codes
ROOT_DEFAULT_DAYS = 3652             # what makeRootCa.sh hard-codes
MAX_DAYS = 3652

CA_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$")
CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")

# The working-slot files and the root originals makeRootCa.sh keeps beside them.
WORKING_SLOT = (("ca.pem", "root-ca.pem"),
                ("ca-do-not-share.key", "root-ca-do-not-share.key"),
                ("ca-trusted.pem", "root-ca-trusted.pem"))

SAN_BEGIN = "# >>> tak-portal: TAK Server certificate names (managed - edits are replaced) >>>"
SAN_END = "# <<< tak-portal: TAK Server certificate names <<<"

def _utcnow():
    """Naive UTC now, matching openssl's notAfter which is parsed naive."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


class CertError(Exception):
    """A refusal with a message meant for the operator. Nothing was changed when it is raised
    before the first step of a job; inside a job the log says what was done."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _run(argv, cwd=None, env=None, input_text=None, timeout=180):
    """Run argv, return (rc, combined output). Never raises on a non-zero exit.
    The portal's service unit runs with UMask=0077 for its own files; TAK's scripts and keytool
    get the 022 a hand run as root has, so certificates, truststores and CRLs come out 644 the way
    installTAK and the TAK docs leave them (keys are made 600 by the tools themselves)."""
    shown = list(argv)
    kw = {}
    if os.name == "posix":
        if sys.version_info >= (3, 9):
            kw["umask"] = 0o022
        else:                                   # Python 3.6-3.8 (RHEL 8): the same through sh
            argv = ["sh", "-c", 'umask 022; exec "$@"', "sh"] + list(argv)
    try:
        r = subprocess.run(argv, cwd=cwd, env=env, input=input_text, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout, **kw)
        return r.returncode, r.stdout or ""
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s: {' '.join(shown[:3])}"
    except Exception as e:  # noqa: BLE001 - reported to the operator
        return 127, f"{type(e).__name__}: {e}"


def _as_tak(argv, env=None):
    """argv run as the tak user. runuser keeps the caller's environment (so passwords travel in
    environ, readable only by root and tak, never in the world-readable cmdline), but it may reset
    PATH from login.defs, so PATH is pinned explicitly."""
    path = (env or {}).get("PATH") or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return ["runuser", "-u", TAK_USER, "--", "env", "PATH=" + path] + list(argv)


def _java_bin_dirs():
    """Directories that may hold keytool: TAK's own setenv.sh JAVA_HOME first, then the JVMs."""
    dirs = []
    setenv = TAK_DIR / "setenv.sh"
    try:
        for line in setenv.read_text(errors="replace").splitlines():
            m = re.match(r"\s*(?:export\s+)?JAVA_HOME=['\"]?([^'\"\s]+)", line)
            if m:
                dirs.append(os.path.join(m.group(1), "bin"))
    except OSError:
        pass
    dirs += sorted(glob.glob("/usr/lib/jvm/*/bin"), reverse=True)
    return [d for d in dirs if os.path.isdir(d)]


def _tak_env(extra=None):
    """Environment for TAK's scripts and keytool: PATH with Java, the subject fields the scripts
    insist on, the certificate password, and MOVE_CA so makeCert.sh ca never prompts."""
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "HOME": "/tmp", "LANG": "C.UTF-8", "MOVE_CA": "true"}
    for d in _java_bin_dirs():
        env["PATH"] = d + ":" + env["PATH"]
    env.update(subject_env())
    env.update(extra or {})
    return env


def _tak_ids():
    if pwd is None:
        raise KeyError(TAK_USER)
    p = pwd.getpwnam(TAK_USER)
    return p.pw_uid, p.pw_gid


def _chown(path, uid, gid):
    if hasattr(os, "chown"):
        os.chown(path, uid, gid)


def unlink_quiet(path):
    """Path.unlink(missing_ok=True), which needs Python 3.8; RHEL 8 ships 3.6."""
    try:
        os.unlink(str(path))
    except FileNotFoundError:
        pass


def own_tak(path, mode=None):
    """Give a file the TAK scripts made or that we wrote back to tak:tak (we run as root)."""
    try:
        uid, gid = _tak_ids()
        _chown(path, uid, gid)
        if mode is not None:
            os.chmod(path, mode)
    except (KeyError, OSError):
        pass


def _copy_as_tak(src, dst, mode=None):
    shutil.copy2(src, dst)
    own_tak(dst, mode)


def first_pem(text):
    m = PEM_RE.search(text or "")
    return m.group(0) if m else ""


def read_pem(path):
    try:
        return first_pem(Path(path).read_text(errors="replace"))
    except OSError:
        return ""


def pem_body(pem):
    """The base64 body without whitespace: equal for the same certificate from any store."""
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem or "", re.S)
    return re.sub(r"\s+", "", m.group(1) if m else (pem or ""))


def pem_info(pem):
    """subject / issuer (RFC 2253), their CNs, notAfter and whether the cert is self-signed."""
    out = {"subject": "", "issuer": "", "cn": "", "issuer_cn": "", "not_after": None,
           "self_signed": False, "days_left": None}
    if not pem:
        return out
    rc, txt = _run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate",
                    "-nameopt", "RFC2253"], input_text=pem, timeout=15)
    if rc != 0:
        return out
    for line in txt.splitlines():
        if line.startswith("subject="):
            out["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            out["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            try:
                out["not_after"] = datetime.strptime(line.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                pass
    out["cn"] = dn_cn(out["subject"])
    out["issuer_cn"] = dn_cn(out["issuer"])
    out["self_signed"] = bool(out["subject"]) and out["subject"] == out["issuer"]
    if out["not_after"]:
        out["days_left"] = (out["not_after"] - _utcnow()).days
    return out


def dn_cn(dn):
    m = re.search(r"(?:^|,)CN=((?:\\,|[^,])+)", dn or "")
    return m.group(1).replace("\\,", ",").strip() if m else ""


def cert_sans(pem):
    """SANs as 'DNS:x' / 'IP:y', or None if unreadable."""
    rc, txt = _run(["openssl", "x509", "-noout", "-ext", "subjectAltName"], input_text=pem, timeout=15)
    if rc != 0:
        return None
    out = []
    for part in txt.split("\n", 1)[-1].split(","):
        p = part.strip()
        if p.startswith("DNS:"):
            out.append("DNS:" + p[4:].lower())
        elif p.startswith("IP Address:"):
            out.append("IP:" + p.split(":", 1)[1].strip())
    return out


def validate_ca_name(name, label="CA name"):
    name = (name or "").strip()
    if not CA_NAME_RE.match(name):
        raise CertError(f"{label} '{name}' is not allowed: letters, numbers, hyphens and dots only "
                        "(for example INTERMEDIATE-CA-02), no spaces or underscores, up to 64 characters.")
    return name


def validate_client_name(name):
    name = (name or "").strip()
    if not CLIENT_NAME_RE.match(name):
        raise CertError(f"Client name '{name}' is not allowed: letters, numbers, dots, hyphens, "
                        "underscores and @ only, no spaces, up to 64 characters.")
    if name.lower() in ("ca", "root-ca", SERVER_CERT_NAME, server_cert_name().lower()) \
            or name.lower().startswith("truststore-") or name.lower().endswith(("-signing", "-le")):
        raise CertError(f"'{name}' is reserved for CA material or the server's own certificate.")
    return name


def suggest_next_name(name):
    m = re.search(r"(\d+)$", name or "")
    if m:
        return name[:m.start()] + f"{int(m.group(1)) + 1:02d}"
    return (name or "INTERMEDIATE-CA") + "-02"


# ---------------------------------------------------------------------------
# cert-metadata.sh, passwords and subject fields
# ---------------------------------------------------------------------------

def _metadata_literals():
    """VAR -> literal value for assignments in cert-metadata.sh that are not shell-templated."""
    out = {}
    try:
        text = CERT_METADATA.read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        m = re.match(r"\s*([A-Z_]+)=(.*)$", line)
        if not m:
            continue
        var, raw = m.group(1), m.group(2).strip()
        d = re.match(r"\$\{" + var + r":-([^}]*)\}$", raw)
        if d and "$" not in d.group(1):
            out[var] = d.group(1).strip("'\"")
            continue
        if raw.startswith("${") or "$" in raw:
            continue
        out[var] = raw.strip("'\"")
    return out


def subject_env(files_dir=FILES_DIR):
    """STATE / CITY / ORGANIZATION / ORGANIZATIONAL_UNIT / COUNTRY for the scripts. Literal values
    in cert-metadata.sh win; anything still templated comes from the root CA's own subject, so a
    box whose metadata was only ever supplied through the environment keeps issuing consistent
    certificates. makeCert.sh refuses to run with STATE, CITY or ORGANIZATIONAL_UNIT empty."""
    lit = _metadata_literals()
    env = {}
    root = pem_info(read_pem(files_dir / "root-ca.pem"))
    from_root = {}
    for key, attr in (("COUNTRY", "C"), ("STATE", "ST"), ("CITY", "L"),
                      ("ORGANIZATION", "O"), ("ORGANIZATIONAL_UNIT", "OU")):
        m = re.search(r"(?:^|,)" + attr + r"=((?:\\,|[^,])+)", root["subject"] or "")
        if m:
            from_root[key] = m.group(1).replace("\\,", ",").strip()
    for key in ("COUNTRY", "STATE", "CITY", "ORGANIZATION", "ORGANIZATIONAL_UNIT"):
        val = lit.get(key) or from_root.get(key) or ""
        if not val and key in ("STATE", "CITY", "ORGANIZATIONAL_UNIT"):
            val = {"STATE": "State", "CITY": "City", "ORGANIZATIONAL_UNIT": "TAK"}[key]
        if val:
            env[key] = val
    return env


def cert_password(override=None):
    """The keystore password TAK is using now. CoreConfig's truststorePass is the one TAK Server
    actually opens the truststore with, so it wins; then a literal CAPASS in cert-metadata.sh;
    then the portal's stored value; then TAK's default."""
    if override:
        return override
    try:
        tls = coreconfig_tls(coreconfig_text())
        if tls.get("truststorePass"):
            return tls["truststorePass"]
    except Exception:  # noqa: BLE001
        pass
    lit = _metadata_literals()
    if lit.get("CAPASS"):
        return lit["CAPASS"]
    return DEFAULT_CERT_PASSWORD


def set_metadata_password(new_pass):
    """Make cert-metadata.sh agree with a new password when its CAPASS / PASS lines are literal
    (an environment override cannot beat a literal). Templated lines are left alone: the
    environment we pass carries the password."""
    try:
        text = CERT_METADATA.read_text(errors="replace")
    except OSError:
        return False
    lines = text.splitlines(keepends=True)
    changed = False
    for i, line in enumerate(lines):
        m = re.match(r"(\s*)(CAPASS|PASS)=(.*)$", line.rstrip("\n"))
        if not m:
            continue
        var, raw = m.group(2), m.group(3).strip()
        d = re.match(r"\$\{" + var + r":-([^}]*)\}$", raw)
        if d and "$" not in d.group(1):       # ${CAPASS:-old}: keep the form, change the default
            lines[i] = f"{m.group(1)}{var}=${{{var}:-{new_pass}}}\n"
            changed = True
        elif "$" not in raw:
            lines[i] = f"{m.group(1)}{var}={json.dumps(new_pass)}\n"
            changed = True
    if changed:
        st = CERT_METADATA.stat()
        CERT_METADATA.write_text("".join(lines))
        _chown(CERT_METADATA, st.st_uid, st.st_gid)
        os.chmod(CERT_METADATA, st.st_mode & 0o7777)
    return changed


# ---------------------------------------------------------------------------
# CoreConfig.xml
# ---------------------------------------------------------------------------

def coreconfig_text(path=CORECONFIG):
    return Path(path).read_text(errors="replace")


def coreconfig_write(text, path=CORECONFIG):
    """Atomic write that keeps tak's ownership and mode, with a one-off backup beside it."""
    path = Path(path)
    st = path.stat()
    backup = path.with_name(path.name + ".portal-backup")
    if not backup.exists():
        shutil.copy2(path, backup)
        _chown(backup, st.st_uid, st.st_gid)
        os.chmod(backup, 0o600)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".CoreConfig-", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    _chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, path)


def _security_tls(text):
    sec = re.search(r"<security\b.*?</security>", text or "", re.S)
    block = sec.group(0) if sec else (text or "")
    m = re.search(r"<tls\b[^>]*>", block)
    return m


def coreconfig_tls(text):
    """keystoreFile / keystorePass / truststoreFile / truststorePass of the main <security><tls>,
    paths made absolute. Federation has a <tls> of its own, which is why we look under <security>."""
    m = _security_tls(text)
    out = {"keystoreFile": "", "keystorePass": "", "truststoreFile": "", "truststorePass": ""}
    if not m:
        return out
    for key in out:
        a = re.search(r"\b" + key + r'="([^"]*)"', m.group(0))
        out[key] = _xml_unescape(a.group(1)) if a else ""
    for key in ("keystoreFile", "truststoreFile"):
        p = out[key]
        if p and not p.startswith("/"):
            out[key] = posixpath.join(TAK_DIR.as_posix(), p)
    return out


def coreconfig_federation_tls(text):
    """keystoreFile / keystorePass / truststoreFile / truststorePass of <federation-server><tls>,
    paths made absolute; all empty when federation has no <tls> of its own."""
    out = {"keystoreFile": "", "keystorePass": "", "truststoreFile": "", "truststorePass": ""}
    fed = re.search(r"<federation-server\b.*?</federation-server>", text or "", re.S)
    m = re.search(r"<tls\b[^>]*>", fed.group(0)) if fed else None
    if not m:
        return out
    for key in out:
        a = re.search(r"\b" + key + r'="([^"]*)"', m.group(0))
        out[key] = _xml_unescape(a.group(1)) if a else ""
    for key in ("keystoreFile", "truststoreFile"):
        p = out[key]
        if p and not p.startswith("/"):
            out[key] = posixpath.join(TAK_DIR.as_posix(), p)
    return out


def federation_enabled(text):
    return bool(re.search(r'<federation\b[^>]*\benableFederation="true"', text or ""))


def coreconfig_signing(text):
    """The <TAKServerCAConfig> that signs enrolled certificates, or {} if TAK Server enrollment
    is not configured."""
    m = re.search(r"<TAKServerCAConfig\b[^>]*>", text or "")
    if not m:
        return {}
    out = {}
    for key in ("keystoreFile", "keystorePass", "validityDays"):
        a = re.search(r"\b" + key + r'="([^"]*)"', m.group(0))
        out[key] = _xml_unescape(a.group(1)) if a else ""
    if out.get("keystoreFile") and not out["keystoreFile"].startswith("/"):
        out["keystoreFile"] = posixpath.join(TAK_DIR.as_posix(), out["keystoreFile"])
    return out


def coreconfig_connection(text):
    """url / username / password of <repository><connection>, for the certificate table."""
    m = re.search(r"<connection\b[^>]*>", text or "")
    out = {"url": "", "username": "", "password": ""}
    if not m:
        return out
    for key in out:
        a = re.search(r"\b" + key + r'="([^"]*)"', m.group(0))
        out[key] = _xml_unescape(a.group(1)) if a else ""
    return out


def coreconfig_connectors(text):
    """Every <connector> under <network>: port, _name, keystoreFile (absolute, '' when the
    connector uses the main <tls> keystore) and whether that file exists. installTAK points 8446
    at certs/files/<host>-le.jks for Let's Encrypt; if certbot failed the file is missing."""
    out = []
    for m in re.finditer(r"<connector\b[^>]*>", text or ""):
        tag = m.group(0)
        if tag.lstrip().startswith("<!--"):
            continue
        attrs = {k: _xml_unescape(v) for k, v in re.findall(r'\b([A-Za-z_]+)="([^"]*)"', tag)}
        ks = attrs.get("keystoreFile", "")
        if ks and not ks.startswith("/"):
            ks = posixpath.join(TAK_DIR.as_posix(), ks)
        out.append({"port": attrs.get("port", ""), "name": attrs.get("_name", ""), "keystoreFile": ks,
                    "exists": bool(ks) and os.path.exists(ks), "clientAuth": attrs.get("clientAuth", "")})
    return out


def coreconfig_reset_connector(text, port="8446"):
    """The <connector> for `port` put back on TAK's own certificate: its keystore attributes
    removed and _name restored to cert_https. Other attributes (clientAuth, enableWebtak) stay.
    Returns (text, changed)."""
    changed = False
    for m in list(re.finditer(r"<connector\b[^>]*>", text or "")):
        tag = m.group(0)
        if not re.search(r'\bport="' + re.escape(port) + r'"', tag) or "keystoreFile" not in tag:
            continue
        new = re.sub(r'\s+(keystore|keystoreFile|keystorePass)="[^"]*"', "", tag)
        new = re.sub(r'\b_name="[^"]*"', '_name="cert_https"', new)
        new = re.sub(r"\s{2,}", " ", new)
        text = text.replace(tag, new, 1)
        changed = True
    return text, changed


def _xml_unescape(s):
    return (s.replace("&quot;", '"').replace("&apos;", "'").replace("&lt;", "<")
             .replace("&gt;", ">").replace("&amp;", "&"))


def _xml_escape(s):
    return (s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;"))


def _set_attr_in(match_text, key, value):
    """Replace key="..." inside one XML start tag, or add it when missing."""
    pat = re.compile(r"(\b" + key + r'=")([^"]*)(")')
    if pat.search(match_text):
        return pat.sub(lambda m: m.group(1) + _xml_escape(value) + m.group(3), match_text, count=1)
    return match_text[:-1].rstrip("/") + f' {key}="{_xml_escape(value)}"' + ("/>" if match_text.endswith("/>") else ">")


def coreconfig_point_at(text, int_name, cert_pass=None, validity_cap=None):
    """CoreConfig with the main truststore and the enrollment signing keystore pointed at
    intermediate `int_name`; optionally every relevant password, and validityDays capped.
    Attribute-targeted, never a blind text replace. Returns (text, [changes])."""
    changes = []
    m = _security_tls(text)
    if m:
        tag = m.group(0)
        new = _set_attr_in(tag, "truststoreFile", f"certs/files/truststore-{int_name}.jks")
        if cert_pass:
            new = _set_attr_in(new, "truststorePass", cert_pass)
            new = _set_attr_in(new, "keystorePass", cert_pass)
        if new != tag:
            # replace the first occurrence inside <security> only
            sec = re.search(r"<security\b.*?</security>", text, re.S)
            if sec:
                block = sec.group(0).replace(tag, new, 1)
                text = text[:sec.start()] + block + text[sec.end():]
            else:
                text = text.replace(tag, new, 1)
            changes.append("truststore")
    if cert_pass:
        # federation's <tls> normally serves the same server keystore, so its password must follow;
        # its truststore is a file of its own and keeps its password
        main_ks = coreconfig_tls(text).get("keystoreFile", "")
        fed = re.search(r"<federation-server\b.*?</federation-server>", text, re.S)
        fm = re.search(r"<tls\b[^>]*>", fed.group(0)) if fed else None
        if fm and main_ks and coreconfig_federation_tls(text).get("keystoreFile") == main_ks:
            new = _set_attr_in(fm.group(0), "keystorePass", cert_pass)
            if new != fm.group(0):
                block = fed.group(0).replace(fm.group(0), new, 1)
                text = text[:fed.start()] + block + text[fed.end():]
                changes.append("federation keystorePass")
    # installTAK: one <crl> per intermediate inside <security><tls>, with x509checkRevocation on.
    # The new intermediate's CRL (makeCert.sh ca writes it) joins the list; old ones stay until Revoke.
    sec = re.search(r"<security\b.*?</security>", text, re.S)
    if sec:
        block = sec.group(0)
        crls = list(re.finditer(r"[ \t]*<crl\b[^>]*/>[ \t]*\r?\n?", block))
        if crls and not any(re.search(r'crlFile="[^"]*/' + re.escape(int_name) + r'\.crl"', c.group(0)) for c in crls):
            last = crls[-1]
            indent = re.match(r"[ \t]*", last.group(0)).group(0)
            el = f'{indent}<crl _name="TAKServer CA {int_name}" crlFile="certs/files/{int_name}.crl"/>\n'
            tail = "" if last.group(0).endswith("\n") else "\n"
            block = block[:last.end()] + tail + el + block[last.end():]
            text = text[:sec.start()] + block + text[sec.end():]
            changes.append("crl")
    m = re.search(r"<TAKServerCAConfig\b[^>]*>", text)
    if m:
        tag = m.group(0)
        new = _set_attr_in(tag, "keystoreFile", f"certs/files/{int_name}-signing.jks")
        for key in ("CAkey", "CAcertificate"):   # installTAK writes these as /opt/tak/certs/files/<INT>
            if re.search(r"\b" + key + r'="', new):
                new = _set_attr_in(new, key, posixpath.join(FILES_DIR.as_posix(), int_name))
        if cert_pass:
            new = _set_attr_in(new, "keystorePass", cert_pass)
        if validity_cap:
            cur = re.search(r'\bvalidityDays="(\d+)"', new)
            if cur and int(cur.group(1)) > validity_cap:
                new = _set_attr_in(new, "validityDays", str(validity_cap))
                changes.append(f"validityDays {cur.group(1)} -> {validity_cap}")
        if new != tag:
            text = text.replace(tag, new, 1)
            changes.append("certificateSigning")
    return text, changes


def server_cert_name(cc_text=None):
    """The name makeCert.sh issued TAK Server's own certificate under: the basename of CoreConfig's
    main keystoreFile (installTAK uses the host name, the TAK docs use takserver)."""
    try:
        text = cc_text if cc_text is not None else coreconfig_text()
    except OSError:
        return SERVER_CERT_NAME
    ks = os.path.basename(coreconfig_tls(text).get("keystoreFile", "") or "")
    if ks.endswith(".jks") and len(ks) > 4:
        return ks[:-4]
    return SERVER_CERT_NAME


def coreconfig_drop_crl(text, ca_name):
    """CoreConfig without the <crl> element that points at certs/files/<ca_name>.crl (installTAK
    adds one per intermediate inside <security><tls>). Returns (text, removed)."""
    pat = re.compile(r"[ \t]*<crl\b[^>]*crlFile=\"[^\"]*/" + re.escape(ca_name) + r"\.crl\"[^>]*/>[ \t]*\r?\n?")
    new, n = pat.subn("", text or "")
    return new, n > 0


def live_truststore_name(cc_text, files_dir=FILES_DIR):
    """The truststore-<INT>.jks TAK Server enforces now. CoreConfig names it; the CN of ca.pem is
    the fallback; a lone candidate is unambiguous. Between several, never guess: ''."""
    have = set(os.listdir(files_dir)) if os.path.isdir(files_dir) else set()
    wanted = []
    ts = coreconfig_tls(cc_text).get("truststoreFile", "")
    if ts:
        wanted.append(os.path.basename(ts))
    cn = pem_info(read_pem(files_dir / "ca.pem"))["cn"]
    if cn:
        wanted.append(f"truststore-{cn}.jks")
    for w in wanted:
        if w in have and _is_int_truststore(w):
            return w
    cands = [f for f in have if _is_int_truststore(f)]
    return cands[0] if len(cands) == 1 else ""


def _is_int_truststore(name):
    return (name.startswith("truststore-") and name.endswith(".jks")
            and name not in ("truststore-root.jks",) and not name.startswith("fed-"))


# ---------------------------------------------------------------------------
# keytool (always as the tak user, password through the environment)
# ---------------------------------------------------------------------------

def _keytool(args, storepass, extra_env=None, timeout=90):
    """keytool as tak. Store passwords go in through `-storepass:env NAME`, so they are never on
    the command line."""
    env = _tak_env({"KT_STOREPASS": storepass, **(extra_env or {})})
    return _run(_as_tak(["keytool"] + args, env), env=env, timeout=timeout)


def parse_keytool_rfc(out):
    """[(alias, 'trusted' | 'key', pem)] from `keytool -list -rfc` output, or None if it is not
    a listing (an error message, an empty store)."""
    if "Alias name:" not in (out or ""):
        return None
    entries = []
    for block in out.split("Alias name:")[1:]:
        alias = block.split("\n", 1)[0].strip()
        kind = "trusted" if "trustedCertEntry" in block else "key"
        pem = first_pem(block)
        if alias and pem:
            entries.append((alias, kind, pem))
    return entries


def keytool_entries(ts_path, storepass):
    """[(alias, 'trusted' | 'key', pem)] of a keystore, or None if it cannot be read."""
    rc, out = _keytool(["-list", "-rfc", "-keystore", str(ts_path), "-storepass:env", "KT_STOREPASS"], storepass)
    if rc != 0:
        return None
    return parse_keytool_rfc(out)


def keytool_delete(ts_path, storepass, alias):
    return _keytool(["-delete", "-alias", alias, "-keystore", str(ts_path), "-storepass:env", "KT_STOREPASS"], storepass)


def keytool_import_cert(ts_path, storepass, alias, pem_path, storetype=None):
    args = ["-importcert", "-noprompt", "-trustcacerts", "-alias", alias, "-file", str(pem_path),
            "-keystore", str(ts_path), "-storepass:env", "KT_STOREPASS"]
    if storetype:
        args += ["-storetype", storetype]
    return _keytool(args, storepass)


def keytool_copy_entry(src, srcpass, alias, dst, dstpass, destalias):
    return _keytool(["-importkeystore", "-noprompt", "-srckeystore", str(src), "-srcstorepass:env", "KT_SRCPASS",
                     "-srcalias", alias, "-destkeystore", str(dst), "-deststorepass:env", "KT_STOREPASS",
                     "-destalias", destalias], dstpass, {"KT_SRCPASS": srcpass})


def keytool_jks_to_p12(src_jks, dst_p12, storepass):
    return _keytool(["-importkeystore", "-noprompt", "-srckeystore", str(src_jks), "-srcstoretype", "JKS",
                     "-srcstorepass:env", "KT_STOREPASS", "-destkeystore", str(dst_p12), "-deststoretype", "PKCS12",
                     "-deststorepass:env", "KT_STOREPASS"], storepass)


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def ca_material_names(files_dir=FILES_DIR, skip=(), server_name=None):
    """Lower-case names that are CA material or the server's own certificate, judged from what
    makeCert.sh ca leaves behind (a .crl, a truststore-NAME.jks, NAME-signing.*) plus the fixed names."""
    names = {"ca", "root-ca", SERVER_CERT_NAME, (server_name or server_cert_name()).lower()} | {s.lower() for s in skip if s}
    for f in os.listdir(files_dir):
        if f.endswith(".crl"):
            names.add(f[:-4].lower())
        elif f.startswith("truststore-") and f.endswith(".jks"):
            names.add(f[len("truststore-"):-4].lower())
    return names


def client_cert_names(files_dir=FILES_DIR, skip=(), server_name=None):
    """Every NAME.p12 that is a client certificate: not the server cert, not CA material, not a
    CA's signing keystore, not a Let's Encrypt keystore. The names Rotate re-issues."""
    cas = ca_material_names(files_dir, skip, server_name)
    names = []
    for f in sorted(os.listdir(files_dir)):
        if not f.endswith(".p12") or f.startswith("truststore-"):
            continue
        name = f[:-4]
        low = name.lower()
        if low in cas or (low.endswith("-signing") and low[:-8] in cas) or low.endswith("-le"):
            continue
        names.append(name)
    return names


def server_cert_mode(files_dir=FILES_DIR, server_name=None):
    """'root', 'intermediate' (signed by the working CA) or 'unknown', read from the files."""
    srv = pem_info(read_pem(files_dir / f"{server_name or server_cert_name()}.pem"))
    root = pem_info(read_pem(files_dir / "root-ca.pem"))
    work = pem_info(read_pem(files_dir / "ca.pem"))
    if not srv["issuer"]:
        return "unknown"
    if root["subject"] and srv["issuer"] == root["subject"]:
        return "root"
    if work["subject"] and srv["issuer"] == work["subject"] and work["subject"] != root["subject"]:
        return "intermediate"
    return "unknown"


def signer_or_default(files_dir=FILES_DIR):
    return "root" if server_cert_mode(files_dir) == "root" else "intermediate"


def live_server_cert(port=8443, host="127.0.0.1"):
    """The certificate TAK presents right now (8443 shares 8089's keystore and stays quiet in the
    logs about a client-certless probe), or '' when it is not answering."""
    rc, out = _run(["openssl", "s_client", "-connect", f"{host}:{port}"], input_text="", timeout=12)
    return first_pem(out) if rc in (0, 1) else ""


def tak_listening(port=8089, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Installed TAK Server version
# ---------------------------------------------------------------------------
# TAK's build names a release "5.4-RELEASE-106" (shortver.txt inside takserver.war, what the web
# UI shows) while the .deb / .rpm carries "5.4-RELEASE106". The package manager is the source of
# truth for what is installed; the war is the fallback and a cross-check.

def normalize_version(v):
    """'5.4-RELEASE106' -> '5.4-RELEASE-106'; anything else unchanged."""
    v = (v or "").strip()
    m = re.match(r"^(\d+(?:\.\d+)*)-([A-Za-z]+)-?(\d+)(.*)$", v)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}{m.group(4)}" if m else v


def _query(argv):
    try:
        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=15)
        return r.returncode, (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def package_version():
    """(version, 'dpkg:<pkg>' | 'rpm:<pkg>') of the installed TAK Server package; ('', '') when
    neither dpkg nor rpm knows one. takserver-core is the split two-box install."""
    if shutil.which("dpkg-query"):
        for pkg in ("takserver", "takserver-core"):
            rc, out = _query(["dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", pkg])
            if rc == 0 and out.startswith("installed "):
                return out.split(None, 1)[1].strip(), "dpkg:" + pkg
    if shutil.which("rpm"):
        for pkg in ("takserver", "takserver-core"):
            rc, out = _query(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg])
            if rc == 0 and out and not out.startswith("package "):
                return out.splitlines()[0].strip(), "rpm:" + pkg
    return "", ""


def war_version(war=None):
    """TAK's own version string from shortver.txt inside takserver.war, '' when unreadable."""
    war = Path(war) if war else TAK_DIR / "takserver.war"
    try:
        with zipfile.ZipFile(str(war)) as z:
            for n in z.namelist():
                if n.endswith("shortver.txt") and n.count("/") <= 2:
                    return z.read(n).decode("ascii", "replace").strip()[:60]
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
        pass
    return ""


_version_cache = {"key": None, "at": 0.0, "value": None}


def installed_version(max_age=30):
    """What is installed, for the dashboard: {'version': TAK's own form, 'package': what dpkg /
    rpm hold, 'source', 'war': what takserver.war says}. Cached until the war changes (an
    install replaces it) or max_age seconds pass."""
    war_path = TAK_DIR / "takserver.war"
    try:
        st = war_path.stat()
        key = (str(war_path), st.st_mtime_ns, st.st_size)
    except OSError:
        key = (str(war_path), 0, 0)
    c = _version_cache
    if c["value"] is not None and c["key"] == key and time.time() - c["at"] < max_age:
        return c["value"]
    pkg, source = package_version()
    war = war_version(war_path)
    value = {"version": normalize_version(pkg) if pkg else war, "package": pkg,
             "source": source or ("war" if war else ""), "war": war}
    c["key"], c["at"], c["value"] = key, time.time(), value
    return value


# ---------------------------------------------------------------------------
# Server certificate names (SANs)
# ---------------------------------------------------------------------------

def expected_san_names(fqdn="", extra=(), server_name=SERVER_CERT_NAME):
    """makeCert's own DNS:<server name> first (it writes that one itself), then the configured
    FQDN, the box's own host name and addresses, localhost."""
    names = ["DNS:" + server_name.lower()]

    def add(n):
        if n not in names:
            names.append(n)
    for host in [fqdn] + list(extra) + [socket.getfqdn(), socket.gethostname()]:
        h = str(host or "").strip().lower().rstrip(".")
        if h and HOST_RE.match(h) and h != "localhost":
            add("DNS:" + h)
    for ip in _host_ips():
        add("IP:" + ip)
    add("DNS:localhost")
    add("IP:127.0.0.1")
    return names


def _host_ips():
    rc, out = _run(["hostname", "-I"], timeout=5)
    ips = []
    if rc == 0:
        for tok in out.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", tok) and not tok.startswith("127."):
                ips.append(tok)
    return ips[:4]


def config_cfg_with_names(text, names, server_name=SERVER_CERT_NAME):
    """config.cfg with a managed [alt_names] block directly above `[ server ]`. makeCert.sh
    appends its own `[alt_names] DNS.1 = <name>` and OpenSSL merges repeated sections, so ours
    starts at .2. Returns None when the file has no `[ server ]` section (left alone)."""
    kept, inside = [], False
    for line in (text or "").splitlines(keepends=True):
        s = line.strip()
        if s == SAN_BEGIN:
            inside = True
            continue
        if inside:
            if s == SAN_END:
                inside = False
            continue
        kept.append(line)
    if inside:
        return None
    # drop the blank line we add after our block, if present
    at = next((i for i, l in enumerate(kept) if re.match(r"^\s*\[\s*server\s*\]\s*$", l)), None)
    if at is None:
        return None
    if at > 0 and kept[at - 1].strip() == "" and at > 1 and kept[at - 2].strip() == "":
        del kept[at - 1]
        at -= 1
    counter = {"DNS": 1, "IP": 1}
    block = [SAN_BEGIN + "\n", "[ alt_names ]\n"]
    for entry in names:
        if entry.lower() == "dns:" + server_name.lower():
            continue
        kind, value = entry.split(":", 1)
        counter[kind] += 1
        block.append(f"{kind}.{counter[kind]} = {value}\n")
    block += [SAN_END + "\n", "\n"]
    if at and not kept[at - 1].endswith("\n"):
        kept[at - 1] += "\n"
    return "".join(kept[:at] + block + kept[at:])


def prepare_server_names(names, log, server_name=SERVER_CERT_NAME):
    try:
        cur = CONFIG_CFG.read_text(errors="replace")
    except OSError as e:
        log(f"  ! Could not read {CONFIG_CFG} ({e}); the server certificate keeps only DNS:{server_name}")
        return False
    new = config_cfg_with_names(cur, names, server_name)
    if new is None:
        log(f"  ! {CONFIG_CFG} has no [ server ] section; the server certificate keeps only DNS:{server_name}")
        return False
    if new != cur:
        st = CONFIG_CFG.stat()
        CONFIG_CFG.write_text(new)
        _chown(CONFIG_CFG, st.st_uid, st.st_gid)
        os.chmod(CONFIG_CFG, st.st_mode & 0o7777)
    log("  Server certificate names: " + ", ".join(n.split(":", 1)[1] for n in names))
    return True


# ---------------------------------------------------------------------------
# Running TAK's scripts
# ---------------------------------------------------------------------------

def _script_with_days(script, days, kind):
    """A tak-owned temporary copy of makeCert.sh / makeRootCa.sh with the hard-coded validity
    replaced, so a chosen validity is honoured without editing TAK's own script."""
    text = Path(script).read_text(errors="replace")
    if kind == "root":
        text = text.replace("-days 3652", f"-days {int(days)}", 1)
    else:
        # the signing line: openssl x509 ... -req -days 730 ...
        text = re.sub(r"(-req -days )730", lambda m: m.group(1) + str(int(days)), text, count=1)
    tmp = CERTS_DIR / f".portal-{Path(script).stem}-{os.getpid()}.sh"
    tmp.write_text(text)
    own_tak(tmp, 0o700)
    return tmp


def makecert(kind, name, log, days=None, cert_pass=None):
    """`makeCert.sh <kind> <name>` as tak, from /opt/tak/certs (the script sources
    cert-metadata.sh and config.cfg by relative path). Returns True on success."""
    cert_pass = cert_pass or cert_password()
    script = CERTS_DIR / "makeCert.sh"
    tmp = None
    if days and kind == "ca":
        tmp = _script_with_days(script, days, "ca")
        script = tmp
    try:
        env = _tak_env({"CAPASS": cert_pass, "PASS": cert_pass})
        rc, out = _run(_as_tak(["bash", str(script), kind, name], env), cwd=str(CERTS_DIR), env=env,
                       input_text="y\n", timeout=300)
        if rc != 0:
            tail = "\n".join(out.strip().splitlines()[-6:])
            log(f"  x makeCert.sh {kind} {name} failed (exit {rc}):\n    " + tail.replace("\n", "\n    "))
            return False
        return True
    finally:
        if tmp:
            try:
                tmp.unlink()
            except OSError:
                pass


def make_root_ca(name, log, days=None, cert_pass=None):
    cert_pass = cert_pass or cert_password()
    script = CERTS_DIR / "makeRootCa.sh"
    tmp = None
    if days and int(days) != ROOT_DEFAULT_DAYS:
        tmp = _script_with_days(script, days, "root")
        script = tmp
    try:
        env = _tak_env({"CAPASS": cert_pass, "PASS": cert_pass})
        rc, out = _run(_as_tak(["bash", str(script), "--ca-name", name], env), cwd=str(CERTS_DIR), env=env, timeout=300)
        if rc != 0:
            tail = "\n".join(out.strip().splitlines()[-6:])
            log(f"  x makeRootCa.sh {name} failed (exit {rc}):\n    " + tail.replace("\n", "\n    "))
            return False
        return True
    finally:
        if tmp:
            try:
                tmp.unlink()
            except OSError:
                pass


def reissue_cert(kind, name, log, cert_pass=None, files_dir=FILES_DIR):
    """makeCert.sh that really replaces NAME.p12 and NAME.jks. makeCert writes both keystores
    with `keytool -importkeystore`, which asks to overwrite an existing alias on stdin; the one
    "y" is eaten by the first keytool and the second keeps the OLD cert. Moving the keystores
    aside first means they are created fresh; they go back if the script fails."""
    aside = []
    for ext in (".p12", ".jks"):
        p = files_dir / f"{name}{ext}"
        if p.exists():
            shutil.move(str(p), str(p) + ".reissue")
            aside.append(p)
    ok = makecert(kind, name, log, cert_pass=cert_pass)
    for p in aside:
        bak = Path(str(p) + ".reissue")
        if ok and p.exists():
            unlink_quiet(bak)
        else:
            if bak.exists():
                shutil.move(str(bak), str(p))
            ok = False
    return ok


def issue_server_cert(signer, log, fqdn="", cert_pass=None, files_dir=FILES_DIR):
    """THE one writer of TAK Server's own 8089/8443 certificate.

    signer='intermediate' signs with the working CA. signer='root' puts the root into the working
    slot for this one run and ALWAYS puts the intermediate back, because anything issued while the
    root sits there would be root-signed too."""
    if signer not in SIGNERS:
        log(f"  x unknown signer {signer!r}")
        return False
    name = server_cert_name()
    prepare_server_names(expected_san_names(fqdn, server_name=name), log, name)
    if signer == "intermediate":
        ok = reissue_cert("server", name, log, cert_pass, files_dir)
        if ok:
            log("  Server certificate signed by the intermediate CA")
        return ok
    missing = [src for _slot, src in WORKING_SLOT if not (files_dir / src).exists()]
    if missing:
        log(f"  x Cannot sign with the root CA: {', '.join(missing)} not found")
        return False
    held = []
    ok = False
    try:
        for slot, _src in WORKING_SLOT:
            p = files_dir / slot
            if p.exists():
                shutil.copy2(p, str(p) + ".hold")
                held.append(p)
        for slot, src in WORKING_SLOT:
            _copy_as_tak(files_dir / src, files_dir / slot)
        ok = reissue_cert("server", name, log, cert_pass, files_dir)
    finally:
        back = True
        for p in held:
            try:
                shutil.move(str(p) + ".hold", str(p))
                own_tak(p)
            except OSError:
                back = False
        for slot, _src in WORKING_SLOT:
            if (files_dir / slot) not in held and (files_dir / slot).exists():
                try:
                    (files_dir / slot).unlink()
                except OSError:
                    back = False
        if not back:
            log(f"  x The intermediate CA was NOT put back in the working slot; restore "
                f"{files_dir}/ca*.hold over ca.pem / ca-do-not-share.key / ca-trusted.pem before "
                "issuing any client certificate")
            ok = False
    if ok:
        log("  Server certificate signed by the root CA")
    return ok


# ---------------------------------------------------------------------------
# TAK Server lifecycle
# ---------------------------------------------------------------------------

def restart_takserver(log, wait_seconds=300, expect_issuer=None):
    """systemctl restart, then wait until 8443 presents a certificate (and the expected issuer,
    when given). Returns the live PEM or ''."""
    rc, out = _run(["systemctl", "restart", TAK_UNIT], timeout=180)
    if rc == 124:
        log("  systemctl restart is taking a while (TAK's stop can be slow); waiting for 8443 anyway")
    elif rc != 0:
        log(f"  x systemctl restart {TAK_UNIT}: {out.strip()[:200]}")
        return ""
    log("  TAK Server restarting; waiting for it to answer on 8443...")
    end = time.time() + wait_seconds
    live = ""
    while time.time() < end:
        time.sleep(5)
        live = live_server_cert()
        if live and (not expect_issuer or pem_info(live)["issuer"] == expect_issuer):
            log(f"  TAK Server is up ({int(wait_seconds - (end - time.time()))}s)")
            return live
    log("  ! TAK Server did not answer on 8443 within the wait; check `journalctl -u takserver`")
    return live


def regrant_admin(names, log):
    """`UserManager.jar certmod -A <name>.pem` for the conventional admin certificates that were
    just reissued. TAK ties the admin role to the certificate's fingerprint, so a reissued
    webadmin would otherwise lose it. Idempotent. Other certificates that had the role need the
    same by hand."""
    todo = [n for n in names if n in ADMIN_CERT_NAMES and (FILES_DIR / f"{n}.pem").exists()]
    if not todo:
        return
    if not USERMANAGER_JAR.exists():
        log(f"  ! {USERMANAGER_JAR} not found; re-grant admin to {', '.join(todo)} by hand")
        return
    for n in todo:
        rc, out = _run(["java", "-jar", str(USERMANAGER_JAR), "certmod", "-A", str(FILES_DIR / f"{n}.pem")],
                       cwd=str(TAK_DIR), env=_tak_env(), timeout=180)
        if rc == 0:
            log(f"  Admin role re-granted to {n}")
        else:
            log(f"  ! Could not re-grant admin to {n}: {out.strip()[-160:]}")


# ---------------------------------------------------------------------------
# Trust list operations
# ---------------------------------------------------------------------------

def carry_forward_truststore(new_ts, prev_ts, prev_pass, cert_pass, old_ca_name, old_pem_path, live, log):
    """Rotate step: the new truststore keeps every CA the live one trusts, so a client cert from
    two rotations back is not refused without a word. Roots are never carried (TAK's trust list
    holds intermediates only); an expired CA is dropped and logged with the live certs that still
    name it; a CA that is not in the live store is not brought back (Revoke may have removed it).
    Returns the lower-case CNs the new store trusts."""
    have = keytool_entries(new_ts, cert_pass) or []
    have_keys = {pem_body(p) for _a, _k, p in have}
    have_aliases = {a.lower() for a, _k, _p in have}
    trusted = {pem_info(p)["cn"].lower() for _a, _k, p in have}
    prev = None
    if prev_ts and os.path.exists(prev_ts) and os.path.realpath(prev_ts) != os.path.realpath(new_ts):
        prev = keytool_entries(prev_ts, prev_pass or cert_pass)
    if prev is None:
        log(f"  ! Could not read the current truststore ({os.path.basename(str(prev_ts or '')) or 'none'}); "
            f"only {old_ca_name} is carried forward")
        prev = []
    kept = []
    for alias, kind, pem in prev:
        if kind != "trusted":
            continue
        info = pem_info(pem)
        if pem_body(pem) in have_keys or info["self_signed"]:
            continue
        if info["not_after"] and info["not_after"] < _utcnow():
            log(f"  ! Dropped {alias}: expired {info['not_after']:%Y-%m-%d} "
                f"({_live_text(live, info['cn'] or alias)} signed by it)")
            continue
        dest = alias
        if dest.lower() in have_aliases and info["cn"]:
            dest = info["cn"]
        while dest.lower() in have_aliases:
            dest += "-prev"
        rc, out = keytool_copy_entry(prev_ts, prev_pass or cert_pass, alias, new_ts, cert_pass, dest)
        if rc == 0:
            have_keys.add(pem_body(pem))
            have_aliases.add(dest.lower())
            trusted.add((info["cn"] or alias).lower())
            kept.append(dest)
        else:
            log(f"  ! Could not carry {alias} forward ({out.strip()[:120]}); "
                f"{_live_text(live, info['cn'] or alias)} depend on it")
    if old_ca_name.lower() not in trusted and os.path.exists(old_pem_path):
        rc, out = keytool_import_cert(new_ts, cert_pass, old_ca_name, old_pem_path)
        if rc == 0:
            trusted.add(old_ca_name.lower())
            kept.append(old_ca_name)
    if old_ca_name.lower() not in trusted:
        log(f"  ! {old_ca_name} is NOT in the new truststore; {_live_text(live, old_ca_name)} depend on it")
    log(f"  Carried forward: {', '.join(kept) if kept else 'none'}")
    for cn, n in sorted((live or {}).items()):
        if n and cn not in trusted:
            log(f"  ! {n} live client cert(s) signed by {cn}, which is not in the truststore: those "
                "clients are refused. Not re-added (Revoke may have removed it on purpose)")
    return trusted


def _live_text(live, cn):
    if live is None:
        return "live cert count unknown"
    n = live.get((cn or "").lower(), 0)
    return f"{n} live client cert{'' if n == 1 else 's'}"


def carry_forward_fed_truststore(backup_dir, cc_text, old_root_pem, new_root, log):
    """Root rotation: makeRootCa.sh writes a fresh fed-truststore.jks holding only the new root,
    which would drop every federation partner CA. Put the previous file back (it keeps its own
    password, the one CoreConfig's <federation-server> has), take our old root and anything it
    signed out of it, and add the new root. Partner roots are self-signed on purpose, so unlike
    TAK's own trust list nothing else is dropped."""
    fed = coreconfig_federation_tls(cc_text)
    ts = fed.get("truststoreFile") or ""
    if not ts:
        return
    name = os.path.basename(ts)
    old = Path(backup_dir) / name
    new = Path(ts)
    if not old.exists():
        return
    fed_pass = fed.get("truststorePass") or ""
    entries = keytool_entries(old, fed_pass) if fed_pass else None
    if entries is None:
        log(f"  ! {name}: the previous one could not be opened with CoreConfig's federation truststorePass; "
            f"left as makeRootCa.sh made it (the new root only). Partner CAs, if any, are in {old}")
        return
    old_subject = pem_info(old_root_pem)["subject"]
    _copy_as_tak(old, new, 0o644)
    kept, dropped = [], []
    for alias, kind, pem in entries:
        ours = kind == "trusted" and (pem_body(pem) == pem_body(old_root_pem)
                                      or bool(old_subject and pem_info(pem)["issuer"] == old_subject))
        if ours and keytool_delete(new, fed_pass, alias)[0] == 0:
            dropped.append(alias)
        else:
            kept.append(alias)
    rc, out = keytool_import_cert(new, fed_pass, new_root.lower(), FILES_DIR / "root-ca.pem")
    if rc != 0:
        log(f"  ! {name}: {new_root} not added: {out.strip()[:160]}")
    own_tak(new, 0o644)
    log(f"  {name}: kept {len(kept)} partner entr{'y' if len(kept) == 1 else 'ies'}"
        f"{' (' + ', '.join(kept) + ')' if kept else ''}, dropped {', '.join(dropped) or 'nothing'}, added {new_root}")


def drop_roots(ts_path, cert_pass, log):
    """TAK Server's own trust list holds intermediates only. Java treats every truststore entry
    as a trust anchor, so with the root in it a client that sends its leaf plus ANY root-signed
    intermediate (including one Revoke just removed) is still accepted. makeCert.sh ca imports
    the root under its CN, so entries are judged by subject == issuer, never by alias.
    Returns (ok, [removed aliases])."""
    entries = keytool_entries(ts_path, cert_pass)
    if entries is None:
        log(f"  x Could not read {os.path.basename(str(ts_path))}")
        return False, []
    roots = [(a, p) for a, k, p in entries if k == "trusted" and pem_info(p)["self_signed"]]
    trusted_total = sum(1 for _a, k, _p in entries if k == "trusted")
    if roots and len(roots) == trusted_total:
        log(f"  x {os.path.basename(str(ts_path))} holds only root CAs; removing them would leave TAK "
            "trusting nothing. Not changed.")
        return False, []
    ok, removed = True, []
    for alias, _pem in roots:
        rc, out = keytool_delete(ts_path, cert_pass, alias)
        if rc != 0:
            ok = False
            log(f"  x Could not remove {alias}: {out.strip()[:160]}")
            continue
        removed.append(alias)
        log(f"  Removed root CA '{alias}' from TAK Server's trust list (clients still get it in their .p12)")
    return ok, removed


def root_signed_dependents(live, files_dir=FILES_DIR):
    """Client certs signed directly by the root, which would be cut off once the root leaves the
    trust list: ([names on disk], live count or None)."""
    root = pem_info(read_pem(files_dir / "root-ca.pem"))
    if not root["subject"]:
        return [], None
    names = []
    for n in client_cert_names(files_dir):
        if pem_info(read_pem(files_dir / f"{n}.pem"))["issuer"] == root["subject"]:
            names.append(n)
    n_live = None if live is None else live.get(root["cn"].lower(), 0)
    return names, n_live


def rebuild_client_truststore(ts_jks, cert_pass, log, files_dir=FILES_DIR):
    """truststore-<INT>.p12, the file handed to devices = TAK's trust list + the root (a
    root-signed server cert chains to nothing else). Built beside the old one and moved over it:
    importing into the existing .p12 would merge, keeping a revoked CA."""
    p12 = Path(str(ts_jks)[:-4] + ".p12")
    new = Path(str(p12) + ".new")
    unlink_quiet(new)
    rc, out = keytool_jks_to_p12(ts_jks, new, cert_pass)
    if rc == 0:
        rc, out = keytool_import_cert(new, cert_pass, "root-ca", files_dir / "root-ca.pem", storetype="PKCS12")
    if rc != 0:
        log(f"  ! {p12.name} not rebuilt: {out.strip()[:160]}")
        unlink_quiet(new)
        return False
    shutil.move(str(new), str(p12))
    own_tak(p12, 0o644)
    log(f"  {p12.name} rebuilt (current CAs + root)")
    return True


# ---------------------------------------------------------------------------
# TAK's certificate table (what is really enrolled)
# ---------------------------------------------------------------------------

def _psql(sql, timeout=30):
    """One statement against the cot database: the CoreConfig connection first, then the
    local postgres superuser over the socket. Returns (ok, text)."""
    conn = coreconfig_connection(coreconfig_text()) if CORECONFIG.exists() else {}
    m = re.match(r"jdbc:postgresql://([^:/]+)(?::(\d+))?/([^?]+)", conn.get("url", "") or "")
    if m and conn.get("username"):
        host, port, db = m.group(1), m.group(2) or "5432", m.group(3)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "PGPASSWORD": conn.get("password", ""),
               "PGCONNECT_TIMEOUT": "8"}
        rc, out = _run(["psql", "-h", host, "-p", port, "-U", conn["username"], "-d", db,
                        "-tAF", "\t", "-c", sql], env=env, timeout=timeout)
        if rc == 0:
            return True, out
    rc, out = _run(["runuser", "-u", "postgres", "--", "psql", "-d", "cot", "-tAF", "\t", "-c", sql],
                   cwd="/", timeout=timeout)
    return rc == 0, out


def live_cert_rows():
    """Each client UID's newest certificate from TAK's `certificate` table:
    [{'uid', 'user', 'issuer_cn', 'subject_cn', 'expires', 'revoked', 'live'}], or (None, error)."""
    sql = ("SELECT DISTINCT ON (client_uid) client_uid, coalesce(nullif(user_dn, ''), creator_dn, ''), "
           "extract(epoch from expiration_date)::bigint, (revocation_date IS NOT NULL), "
           "replace(replace(certificate, chr(13), ''), chr(10), '') FROM certificate "
           "WHERE coalesce(client_uid, '') <> '' ORDER BY client_uid, issuance_date DESC")
    ok, out = _psql(sql)
    if not ok:
        err = (out.strip().splitlines() or ["query failed"])[-1][:200]
        return None, f"TAK certificate table: {err}"
    rows = []
    now = time.time()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        body = re.sub(r"-----(BEGIN|END) CERTIFICATE-----|\s", "", parts[4])
        pem = ("-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
               + "\n-----END CERTIFICATE-----\n") if body else ""
        info = pem_info(pem)
        try:
            expires = int(parts[2])
        except ValueError:
            expires = None
        revoked = parts[3] == "t"
        rows.append({"uid": parts[0], "user": dn_cn(parts[1]) or parts[1][:120],
                     "issuer_cn": info["issuer_cn"], "subject_cn": info["cn"], "expires": expires,
                     "revoked": revoked, "live": bool(pem) and not revoked and not (expires and expires < now)})
    return rows, ""


def live_counts_by_issuer(rows):
    counts = {}
    for r in rows or []:
        if r.get("live"):
            k = (r.get("issuer_cn") or "").lower()
            counts[k] = counts.get(k, 0) + 1
    return counts


def live_counts():
    rows, _err = live_cert_rows()
    return None if rows is None else live_counts_by_issuer(rows)


# ---------------------------------------------------------------------------
# Status for the page
# ---------------------------------------------------------------------------

def installed():
    return (CERTS_DIR / "makeCert.sh").exists() and FILES_DIR.is_dir()


def preflight():
    problems = []
    if getattr(os, "geteuid", lambda: -1)() != 0:
        problems.append("The portal is not running as root; certificate operations need root.")
    try:
        _tak_ids()
    except KeyError:
        problems.append(f"No '{TAK_USER}' system user: this portal handles native TAK Server installs only.")
    if not installed():
        problems.append(f"TAK Server certificate scripts not found under {CERTS_DIR}.")
    if not CORECONFIG.exists():
        problems.append(f"{CORECONFIG} not found.")
    if not shutil.which("openssl"):
        problems.append("openssl is not installed.")
    env = _tak_env()
    if not any(os.path.exists(os.path.join(d, "keytool")) for d in env["PATH"].split(":")):
        problems.append("keytool (Java) not found on PATH; TAK Server needs a JDK/JRE, so check /opt/tak/setenv.sh.")
    return problems


def pki_status(fqdn="", rotation_state=None):
    """Everything the Certificates cards show, in one call."""
    st = {"installed": installed(), "problems": preflight(), "root": None, "intermediate": None,
          "server": None, "truststore": None, "clients": [], "suggested_name": "",
          "suggested_root": "", "password": "", "rotation": rotation_state or {}}
    if not st["installed"]:
        return st
    pw = cert_password()
    st["password"] = pw
    for key, fn in (("root", "root-ca.pem"), ("intermediate", "ca.pem")):
        info = pem_info(read_pem(FILES_DIR / fn))
        if info["subject"]:
            st[key] = {"name": info["cn"], "file": fn, "expires": info["not_after"].strftime("%Y-%m-%d") if info["not_after"] else "",
                       "days_left": info["days_left"], "self_signed": info["self_signed"]}
    cur_cn = (st["intermediate"] or {}).get("name", "").lower()
    root_cn = (st["root"] or {}).get("name", "").lower()
    if st["intermediate"]:
        st["suggested_name"] = suggest_next_name(st["intermediate"]["name"])
    if st["root"]:
        st["suggested_root"] = suggest_next_name(st["root"]["name"])
    # server certificate
    srv_name = server_cert_name()
    srv_file = pem_info(read_pem(FILES_DIR / f"{srv_name}.pem"))
    live = live_server_cert()
    live_info = pem_info(live) if live else {}
    want = expected_san_names(fqdn, server_name=srv_name)
    live_sans = cert_sans(live) if live else None
    st["server"] = {"name": srv_name, "mode": server_cert_mode(server_name=srv_name), "issuer_cn": srv_file["issuer_cn"],
                    "expires": srv_file["not_after"].strftime("%Y-%m-%d") if srv_file["not_after"] else "",
                    "days_left": srv_file["days_left"], "live": bool(live),
                    "live_issuer_cn": live_info.get("issuer_cn", ""),
                    "expected_names": [n.split(":", 1)[1] for n in want],
                    "live_names": [n.split(":", 1)[1] for n in (live_sans or [])],
                    "missing_names": [n.split(":", 1)[1] for n in want if live_sans is not None and n not in live_sans],
                    "root_key_present": (FILES_DIR / "root-ca-do-not-share.key").exists()}
    # trust list
    try:
        cc = coreconfig_text()
    except OSError:
        cc = ""
    ts_name = live_truststore_name(cc)
    if ts_name:
        entries = keytool_entries(FILES_DIR / ts_name, pw)
        rows = []
        if entries is not None:
            for alias, kind, pem in entries:
                info = pem_info(pem)
                cn = info["cn"]
                role = ("root" if info["self_signed"] else "current" if cn.lower() == cur_cn
                        else "old" if kind == "trusted" else "key")
                rows.append({"alias": alias, "cn": cn, "kind": kind, "role": role,
                             "expires": info["not_after"].strftime("%Y-%m-%d") if info["not_after"] else "",
                             "days_left": info["days_left"]})
        p12 = ts_name[:-4] + ".p12"
        st["truststore"] = {"file": ts_name, "readable": entries is not None, "entries": rows,
                            "p12": p12 if (FILES_DIR / p12).exists() else "",
                            "signing": coreconfig_signing(cc).get("keystoreFile", ""),
                            "validity_days": coreconfig_signing(cc).get("validityDays", ""),
                            "has_root": any(r["role"] == "root" for r in rows)}
    # connectors (8446 Let's Encrypt, present or dangling)
    try:
        st["connectors"] = coreconfig_connectors(cc)
    except Exception:  # noqa: BLE001
        st["connectors"] = []
    st["dangling_connectors"] = [c for c in st["connectors"] if c["keystoreFile"] and not c["exists"]]
    # client certs
    for n in client_cert_names():
        info = pem_info(read_pem(FILES_DIR / f"{n}.pem"))
        issuer = info["issuer_cn"].lower()
        st["clients"].append({"name": n, "issuer_cn": info["issuer_cn"],
                              "expires": info["not_after"].strftime("%Y-%m-%d") if info["not_after"] else "",
                              "days_left": info["days_left"],
                              "on_current": bool(cur_cn) and issuer == cur_cn,
                              "root_signed": bool(root_cn) and issuer == root_cn})
    return st


# ---------------------------------------------------------------------------
# Jobs. Each takes a log(line) callback and returns a result dict; CertError aborts cleanly.
# ---------------------------------------------------------------------------

_job_lock = __import__("threading").Lock()


def _acquire():
    if not _job_lock.acquire(blocking=False):
        raise CertError("A certificate operation is already running.")


def _release():
    try:
        _job_lock.release()
    except RuntimeError:
        pass


def _require_files(*names):
    for n in names:
        if not (FILES_DIR / n).exists():
            raise CertError(f"{FILES_DIR / n} not found.")


def rotate_intermediate(new_name, log, days=INTERMEDIATE_DEFAULT_DAYS, new_password="", fqdn="",
                        reissue_clients=True):
    """Rotate the intermediate CA. See the module docstring for the model. reissue_clients=False
    is the myTeckNet-guide behaviour: the client certificates on this server stay on the old CA
    (still trusted until Revoke) and only the server certificate moves."""
    problems = preflight()
    if problems:
        raise CertError(" ".join(problems))
    new_name = validate_ca_name(new_name, "New CA name")
    _require_files("root-ca.pem", "root-ca-do-not-share.key", "ca.pem", "ca-do-not-share.key")
    old = pem_info(read_pem(FILES_DIR / "ca.pem"))
    root = pem_info(read_pem(FILES_DIR / "root-ca.pem"))
    if not old["cn"]:
        raise CertError("Could not read the current intermediate CA name from ca.pem.")
    if old["self_signed"]:
        raise CertError("ca.pem is the root CA itself (no intermediate in the working slot). Create an "
                        "intermediate with makeCert.sh ca first, or use Rotate Root CA.")
    if new_name.lower() == old["cn"].lower():
        raise CertError(f"The new name must differ from the current intermediate ({old['cn']}).")
    for f in (f"{new_name}.pem", f"truststore-{new_name}.jks", f"{new_name}-signing.jks"):
        if (FILES_DIR / f).exists():
            raise CertError(f"{f} already exists; pick a name that has not been used on this server.")
    try:
        days = max(1, min(MAX_DAYS, int(days or INTERMEDIATE_DEFAULT_DAYS)))
    except (TypeError, ValueError):
        days = INTERMEDIATE_DEFAULT_DAYS
    if root["days_left"] is not None and root["days_left"] > 0:
        days = min(days, root["days_left"])
    _acquire()
    try:
        cc = coreconfig_text()
        prev_tls = coreconfig_tls(cc)
        prev_pass = prev_tls.get("truststorePass") or cert_password()
        cert_pass = new_password or cert_password()
        signer = signer_or_default()
        log(f"=== Rotating intermediate CA: {old['cn']} -> {new_name} ===")
        log(f"  Server certificate is signed by the {signer} CA")
        if signer != "root":
            log("  ! Every device will be disconnected until it re-enrolls: the server certificate "
                "chains through the intermediate. Switch to root-signed first to avoid that next time.")
        log(f"  New intermediate validity: {days} days" + (" (capped by the root CA's remaining life)"
                                                           if root["days_left"] and days == root["days_left"] else ""))
        old_pem_path = FILES_DIR / f"{old['cn']}.pem"
        if not old_pem_path.exists():
            _copy_as_tak(FILES_DIR / "ca.pem", old_pem_path, 0o644)
            log(f"  Saved the current CA as {old_pem_path.name}")
        if new_password:
            set_metadata_password(new_password)

        log("Step 1/7: Putting the root CA in the working slot (so the new intermediate is signed by the root)...")
        for slot, src in WORKING_SLOT:
            _copy_as_tak(FILES_DIR / src, FILES_DIR / slot)

        log(f"Step 2/7: Creating intermediate CA {new_name}...")
        if not makecert("ca", new_name, log, days=days, cert_pass=cert_pass):
            raise CertError("Creating the new intermediate CA failed. The working slot now holds the ROOT CA: "
                            f"copy {old['cn']}.pem/.key/-trusted.pem back over ca.pem / ca-do-not-share.key / "
                            "ca-trusted.pem before issuing anything.")
        new_info = pem_info(read_pem(FILES_DIR / "ca.pem"))
        if new_info["cn"].lower() != new_name.lower():
            raise CertError(f"makeCert.sh did not move {new_name} into the working slot (ca.pem is {new_info['cn']}).")
        log(f"  {new_name} created, signed by {new_info['issuer_cn']}, valid until "
            f"{new_info['not_after']:%Y-%m-%d}" if new_info["not_after"] else f"  {new_name} created")

        log("Step 3/7: Reissuing the server certificate...")
        if not issue_server_cert(signer, log, fqdn, cert_pass):
            raise CertError("Reissuing the server certificate failed.")

        log("Step 4/7: Reissuing client certificates on the new CA...")
        done, failed = [], []
        if reissue_clients:
            for name in client_cert_names(skip=(old["cn"], new_name)):
                log(f"  Reissuing {name}")
                if reissue_cert("client", name, log, cert_pass):
                    done.append(name)
                else:
                    failed.append(name)
            log(f"  {len(done)} client certificate(s) reissued" + (f"; failed: {', '.join(failed)}" if failed else ""))
            admins = [n for n in done if n in ADMIN_CERT_NAMES]
            if admins:
                log(f"  ! {', '.join(admins)}.p12 changed: import the new file into your browser before you revoke "
                    f"{old['cn']} (the old one keeps working until then)")
        else:
            log(f"  Skipped as asked: the certificates on this server stay on {old['cn']}, which is still trusted "
                "until you revoke it; reissue them before that")

        log("Step 5/7: Building the new trust list...")
        new_ts = FILES_DIR / f"truststore-{new_name}.jks"
        prev_ts = prev_tls.get("truststoreFile") or str(FILES_DIR / f"truststore-{old['cn']}.jks")
        live = live_counts()
        if live is None:
            log("  ! Could not read TAK's certificate table; live certificate counts unavailable")
        carry_forward_truststore(str(new_ts), prev_ts, prev_pass, cert_pass, old["cn"], str(old_pem_path), live, log)
        deps, n_live = root_signed_dependents(live)
        if deps or n_live:
            log(f"  ! Root CA kept in the trust list: certificates signed directly by it exist "
                f"({', '.join(deps) or ''}{'; ' if deps and n_live else ''}{str(n_live) + ' live' if n_live else ''}). "
                "Revoke will refuse until they are reissued.")
        else:
            drop_roots(new_ts, cert_pass, log)
        rebuild_client_truststore(new_ts, cert_pass, log)

        log("Step 6/7: Updating CoreConfig.xml...")
        cap = max(1, (new_info["days_left"] or days) - 1)
        text, changes = coreconfig_point_at(coreconfig_text(), new_name, cert_pass if new_password else None, cap)
        if changes:
            coreconfig_write(text)
        log("  " + (", ".join(changes) if changes else "nothing to change"))
        _point_example_at(new_name, cert_pass if new_password else None, cap, log)

        log("Step 7/7: Restarting TAK Server...")
        live_pem = restart_takserver(log)
        if live_pem:
            log(f"  8443 presents a certificate issued by {pem_info(live_pem)['issuer_cn']}")
        regrant_admin(done, log)

        log("=== ROTATION COMPLETE ===")
        log(f"  Current intermediate: {new_name}. {old['cn']} stays trusted until you Revoke it.")
        if signer == "root":
            log("  Devices keep connecting. Hand out the new truststore / connection package and have users "
                "re-enroll at their own pace; use 'Live certificates by CA' to see who is left.")
        else:
            log("  Devices are disconnected until they import the new truststore or re-enroll.")
        return {"old": old["cn"], "new": new_name, "signer": signer, "at": int(time.time())}
    finally:
        _release()


def _point_example_at(int_name, cert_pass, cap, log):
    """CoreConfig.example.xml too, when present: TAK regenerates CoreConfig.xml from it if the
    real one ever goes missing, and installTAK edits the example as the source of truth."""
    ex = TAK_DIR / "CoreConfig.example.xml"
    if not ex.exists():
        return
    try:
        text, changes = coreconfig_point_at(ex.read_text(errors="replace"), int_name, cert_pass, cap)
        if changes:
            coreconfig_write(text, ex)
            log("  CoreConfig.example.xml: " + ", ".join(changes))
    except Exception as e:  # noqa: BLE001
        log(f"  ! CoreConfig.example.xml not updated: {e}")


def revoke_old_ca(alias, log, fqdn=""):
    """Remove an old intermediate from TAK Server's trust list, airtight: every self-signed root
    leaves too, so a client cannot get back in by sending the revoked CA in its own chain."""
    problems = preflight()
    if problems:
        raise CertError(" ".join(problems))
    alias = (alias or "").strip()
    if not alias:
        raise CertError("Which CA to revoke is required.")
    cc = coreconfig_text()
    ts_name = live_truststore_name(cc)
    if not ts_name:
        raise CertError("Could not tell which truststore TAK Server is using. Nothing was changed.")
    ts_path = FILES_DIR / ts_name
    cert_pass = cert_password()
    entries = keytool_entries(ts_path, cert_pass)
    if entries is None:
        raise CertError(f"Could not read {ts_name}. Nothing was changed.")
    target = [p for a, k, p in entries if a.lower() == alias.lower() and k == "trusted"]
    if not target:
        raise CertError(f"'{alias}' is not a trusted entry in {ts_name}. Nothing was changed.")
    tinfo = pem_info(target[0])
    cur = read_pem(FILES_DIR / "ca.pem")
    if pem_body(target[0]) == pem_body(cur):
        raise CertError(f"'{alias}' is the current intermediate CA; revoking it would cut off every device.")
    if tinfo["self_signed"]:
        raise CertError(f"'{alias}' is a root CA. Revoke removes roots from the trust list on its own; pick an old intermediate.")
    live = live_counts()
    deps, n_live = root_signed_dependents(live)
    if deps or n_live:
        raise CertError("Certificates signed directly by the root CA exist "
                        f"({', '.join(deps) or ''}{'; ' if deps and n_live else ''}{str(n_live) + ' live' if n_live else ''}). "
                        "Revoke takes the root out of the trust list, which would cut those off. Reissue them first.")
    srv_name = server_cert_name(cc)
    srv = pem_info(read_pem(FILES_DIR / f"{srv_name}.pem"))
    ks = os.path.basename(coreconfig_tls(cc).get("keystoreFile", "") or "")
    own_cert = (FILES_DIR / f"{srv_name}.key").exists() and (FILES_DIR / f"{srv_name}.pem").exists()
    _acquire()
    try:
        log(f"=== Revoking {alias} ({tinfo['cn']}) ===")
        n_cut = (live or {}).get((tinfo["cn"] or "").lower(), 0)
        if live is None:
            log("  ! Could not read the certificate table; how many devices are still on this CA is unknown")
        elif n_cut:
            log(f"  ! {n_cut} live device certificate(s) enrolled on {tinfo['cn']} will be refused from now on; those users must re-enroll")
        else:
            log(f"  No live device certificate on {tinfo['cn']} in the certificate table")
        problems = []
        log("Step 1/5: Server certificate...")
        if not own_cert:
            log(f"  8089 presents {ks} (a custom certificate); left as it is")
        elif srv["issuer"] == tinfo["subject"]:
            log("  It chains through the CA being revoked; reissuing it with the current intermediate")
            if not issue_server_cert("intermediate", log, fqdn, cert_pass):
                raise CertError("Reissuing the server certificate failed; nothing was revoked.")
        else:
            log(f"  Signed by {srv['issuer_cn']}; it does not depend on {alias}, left as it is")
        log(f"Step 2/5: Removing {alias} from {ts_name}...")
        rc, out = keytool_delete(ts_path, cert_pass, alias)
        if rc != 0:
            raise CertError(f"keytool could not remove {alias}: {out.strip()[:160]}")
        log(f"  {alias} removed")
        log("Step 3/5: Removing root CAs from TAK Server's trust list...")
        ok, removed = drop_roots(ts_path, cert_pass, log)
        if not ok:
            problems.append("a root CA is still in the trust list, so a client could get in by sending "
                            f"{alias} in its own chain")
        elif not removed:
            log("  No root CA in the trust list")
        log("Step 4/5: Rebuilding the truststore handed to devices...")
        if not rebuild_client_truststore(ts_path, cert_pass, log):
            problems.append(f"{ts_name[:-4]}.p12 was not rebuilt and may still list {alias}")
        for cc_path in (CORECONFIG, TAK_DIR / "CoreConfig.example.xml"):
            try:
                if cc_path.exists():
                    text, removed = coreconfig_drop_crl(cc_path.read_text(errors="replace"), tinfo["cn"] or alias)
                    if removed:
                        coreconfig_write(text, cc_path)
                        log(f"  Removed the {tinfo['cn'] or alias} CRL entry from {cc_path.name}")
            except Exception as e:  # noqa: BLE001
                log(f"  ! {cc_path.name} CRL entry not removed: {e}")
        log("Step 5/5: Restarting TAK Server...")
        restart_takserver(log)
        if problems:
            log("=== REVOKE DONE WITH WARNINGS ===")
            for p in problems:
                log("  ! " + p)
        else:
            log("=== REVOKE COMPLETE ===")
        log(f"  Clients still holding certificates from {alias} must re-enroll.")
        return {"alias": alias, "cn": tinfo["cn"], "problems": problems}
    finally:
        _release()


def rotate_root(new_root, new_int, log, root_days=ROOT_DEFAULT_DAYS, int_days=INTERMEDIATE_DEFAULT_DAYS,
                new_password="", fqdn=""):
    """Full PKI rebuild: new root, new intermediate, new server cert, admin and user client certs.
    Every device must re-enroll. The old files dir is kept as a tak-owned backup."""
    problems = preflight()
    if problems:
        raise CertError(" ".join(problems))
    new_root = validate_ca_name(new_root, "New root CA name")
    new_int = validate_ca_name(new_int, "New intermediate CA name")
    if new_root.lower() == new_int.lower():
        raise CertError("The root and intermediate names must differ.")
    _require_files("root-ca.pem")
    old_root = pem_info(read_pem(FILES_DIR / "root-ca.pem"))
    old_int = pem_info(read_pem(FILES_DIR / "ca.pem"))
    try:
        root_days = max(365, min(MAX_DAYS, int(root_days or ROOT_DEFAULT_DAYS)))
        int_days = max(1, min(root_days, int(int_days or INTERMEDIATE_DEFAULT_DAYS)))
    except (TypeError, ValueError):
        root_days, int_days = ROOT_DEFAULT_DAYS, INTERMEDIATE_DEFAULT_DAYS
    _acquire()
    try:
        cc = coreconfig_text()
        cert_pass = new_password or cert_password()
        signer = signer_or_default()
        clients_before = client_cert_names()
        old_root_pem = read_pem(FILES_DIR / "root-ca.pem")
        log(f"=== Rotating ROOT CA: {old_root['cn']} -> {new_root}, intermediate {old_int['cn'] or '-'} -> {new_int} ===")
        if new_password:
            set_metadata_password(new_password)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = CERTS_DIR / f"files.before-root-rotate-{stamp}"
        log(f"Step 1/7: Moving the old certificate files to {backup.name}...")
        keep = [f for f in os.listdir(FILES_DIR) if "-le." in f or f.endswith("-le.jks") or f.endswith("-le.p12")]
        shutil.move(str(FILES_DIR), str(backup))
        own_tak(backup, 0o700)
        FILES_DIR.mkdir(mode=0o755)
        own_tak(FILES_DIR, 0o755)   # as makeRootCa.sh run by hand leaves it
        for f in keep:
            _copy_as_tak(backup / f, FILES_DIR / f)
            log(f"  Kept {f} (not signed by our CA)")
        log(f"Step 2/7: Creating root CA {new_root} ({root_days} days)...")
        if not make_root_ca(new_root, log, days=root_days, cert_pass=cert_pass):
            raise CertError(f"makeRootCa.sh failed. The previous PKI is intact in {backup}; move it back to {FILES_DIR}.")
        log(f"Step 3/7: Creating intermediate CA {new_int} ({int_days} days)...")
        if not makecert("ca", new_int, log, days=int_days, cert_pass=cert_pass):
            raise CertError(f"makeCert.sh ca failed. The previous PKI is intact in {backup}; move it back to {FILES_DIR}.")
        log("Step 4/7: Creating the server certificate...")
        if not issue_server_cert(signer, log, fqdn, cert_pass):
            raise CertError(f"Server certificate failed. The previous PKI is intact in {backup}.")
        log("Step 5/7: Creating client certificates...")
        wanted = list(dict.fromkeys(list(clients_before) or ["admin", "user"]))
        made = []
        for name in wanted:
            log(f"  {name}")
            if makecert("client", name, log, cert_pass=cert_pass):
                made.append(name)
        log("Step 6/7: Trust list and CoreConfig...")
        new_ts = FILES_DIR / f"truststore-{new_int}.jks"
        drop_roots(new_ts, cert_pass, log)
        rebuild_client_truststore(new_ts, cert_pass, log)
        carry_forward_fed_truststore(backup, cc, old_root_pem, new_root, log)
        text, changes = coreconfig_point_at(coreconfig_text(), new_int, cert_pass if new_password else None,
                                            max(1, int_days - 1))
        if old_int["cn"]:
            text, _dropped = coreconfig_drop_crl(text, old_int["cn"])
        if changes:
            coreconfig_write(text)
        log("  CoreConfig: " + (", ".join(changes) if changes else "nothing to change"))
        _point_example_at(new_int, cert_pass if new_password else None, max(1, int_days - 1), log)
        log("Step 7/7: Restarting TAK Server...")
        restart_takserver(log)
        regrant_admin(made, log)
        log("=== ROOT CA ROTATION COMPLETE ===")
        log("  Every device must import the new truststore or re-enroll. The old PKI is in "
            f"{backup} (owned by {TAK_USER}, mode 700; keep or delete).")
        if federation_enabled(cc):
            log(f"  Federation is enabled: partners that trust this server must import the new root "
                f"({new_root}, files/root-ca.pem); their CAs were carried over.")
        return {"root": new_root, "intermediate": new_int, "backup": str(backup), "at": int(time.time())}
    finally:
        _release()


def switch_signer(signer, log, fqdn=""):
    """Reissue TAK Server's own certificate signed by the root or the intermediate CA. Backs
    takserver.* up, verifies the live issuer after the restart, puts the old files back on failure."""
    problems = preflight()
    if problems:
        raise CertError(" ".join(problems))
    if signer not in SIGNERS:
        raise CertError("signer must be root or intermediate")
    cc = coreconfig_text()
    srv_name = server_cert_name(cc)
    ks = os.path.basename(coreconfig_tls(cc).get("keystoreFile", "") or "")
    if not ((FILES_DIR / f"{srv_name}.key").exists() and (FILES_DIR / f"{srv_name}.pem").exists()):
        raise CertError(f"TAK Server presents {ks or 'an unknown keystore'} on 8089, which makeCert.sh did not issue "
                        "(no matching .pem/.key in certs/files). Switching does not apply.")
    if signer == "root" and not (FILES_DIR / "root-ca-do-not-share.key").exists():
        raise CertError("The root CA's private key is not on this server, so the certificate cannot be signed by it.")
    want = pem_info(read_pem(FILES_DIR / ("root-ca.pem" if signer == "root" else "ca.pem")))["subject"]
    if not want:
        raise CertError("Could not read the CA certificate to sign with.")
    _acquire()
    try:
        return _reissue_server_job(signer, want, log, fqdn, f"Switching TAK Server's certificate to the {signer} CA")
    finally:
        _release()


def reissue_server(log, fqdn=""):
    """Reissue the server certificate with this box's names, same signer."""
    problems = preflight()
    if problems:
        raise CertError(" ".join(problems))
    signer = signer_or_default()
    want = pem_info(read_pem(FILES_DIR / ("root-ca.pem" if signer == "root" else "ca.pem")))["subject"]
    _acquire()
    try:
        return _reissue_server_job(signer, want, log, fqdn, "Reissuing TAK Server's certificate with this server's names")
    finally:
        _release()


def _reissue_server_job(signer, want_issuer, log, fqdn, title):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    srv_name = server_cert_name()
    files = [FILES_DIR / f"{srv_name}.{ext}" for ext in ("pem", "key", "p12", "jks", "csr")]
    backed = []

    def restore():
        ok = True
        for p in backed:
            try:
                shutil.copy2(str(p) + "." + stamp, p)
                own_tak(p)
            except OSError:
                ok = False
        log("  Previous certificate restored" if ok else f"  x Restore incomplete; backups are {FILES_DIR}/{srv_name}.*.{stamp}")
    log(f"=== {title} ===")
    log("Step 1/3: Backing up the current server certificate...")
    for p in files:
        if p.exists():
            shutil.copy2(p, str(p) + "." + stamp)
            own_tak(Path(str(p) + "." + stamp))
            backed.append(p)
    log(f"  Saved as {srv_name}.*.{stamp}")
    log(f"Step 2/3: Reissuing, signed by the {signer} CA...")
    if not issue_server_cert(signer, log, fqdn, cert_password()):
        restore()
        raise CertError("Reissuing the certificate failed; the previous one was put back.")
    got = pem_info(read_pem(FILES_DIR / f"{srv_name}.pem"))
    if got["issuer"] != want_issuer:
        restore()
        raise CertError(f"The new certificate is signed by {got['issuer_cn'] or 'nobody'}, not the {signer} CA; the previous one was put back.")
    log("Step 3/3: Restarting TAK Server...")
    live = restart_takserver(log, expect_issuer=want_issuer)
    if not live or pem_info(live)["issuer"] != want_issuer:
        restore()
        _run(["systemctl", "restart", TAK_UNIT], timeout=180)
        raise CertError("TAK Server did not come back presenting the new certificate; the previous one was put back.")
    for p in backed:
        for old in FILES_DIR.glob(f"{p.name}.[0-9]*-[0-9]*"):
            if not old.name.endswith("." + stamp):
                unlink_quiet(old)
    log(f"  Backups of the previous certificate: {FILES_DIR}/{srv_name}.*.{stamp}")
    log(f"=== DONE: TAK Server presents a certificate signed by {got['issuer_cn']} ===")
    return {"signer": signer, "issuer_cn": got["issuer_cn"]}


def reset_connector_8446(log):
    """Put the 8446 connector back on TAK's own certificate when it points at a keystore that
    does not exist (installTAK's Let's Encrypt step after a failed certbot run). Also disables the
    renew cron that would otherwise restart TAK Server twice a day over the missing files."""
    problems = preflight()
    if problems:
        raise CertError(" ".join(problems))
    cc = coreconfig_text()
    dangling = [c for c in coreconfig_connectors(cc) if c["port"] == "8446" and c["keystoreFile"] and not c["exists"]]
    if not dangling:
        raise CertError("The 8446 connector's keystore exists (or 8446 uses TAK's own certificate already). Nothing to fix.")
    _acquire()
    try:
        log("=== Putting 8446 back on TAK Server's own certificate ===")
        log(f"  CoreConfig points 8446 at {dangling[0]['keystoreFile']}, which does not exist")
        for cc_path in (CORECONFIG, TAK_DIR / "CoreConfig.example.xml"):
            if not cc_path.exists():
                continue
            text, changed = coreconfig_reset_connector(cc_path.read_text(errors="replace"), "8446")
            if changed:
                coreconfig_write(text, cc_path)
                log(f"  {cc_path.name}: connector reset to cert_https")
        renew = TAK_DIR / "renew-tak-le"
        for cron in (Path("/etc/cron.d/certbot-tak-le"),):
            try:
                if cron.exists() and "renew-tak-le" in cron.read_text(errors="replace"):
                    cron.unlink()
                    log(f"  Removed {cron} (it would restart TAK Server every 12 h over the missing certificate)")
            except OSError as e:
                log(f"  ! Could not remove {cron}: {e}")
        try:
            crontab = Path("/etc/crontab")
            if crontab.exists():
                lines = crontab.read_text(errors="replace").splitlines(keepends=True)
                kept = [l for l in lines if "renew-tak-le" not in l]
                if len(kept) != len(lines):
                    crontab.write_text("".join(kept))
                    log("  Removed the renew-tak-le line from /etc/crontab")
        except OSError as e:
            log(f"  ! /etc/crontab not updated: {e}")
        if renew.exists():
            log(f"  Left {renew} in place (harmless without the cron entries); delete it if you never want Let's Encrypt here")
        log("Restarting TAK Server...")
        restart_takserver(log)
        rc, out = _run(["openssl", "s_client", "-connect", "127.0.0.1:8446"], input_text="", timeout=12)
        pem = first_pem(out) if rc in (0, 1) else ""
        if pem:
            log(f"  8446 presents a certificate issued by {pem_info(pem)['issuer_cn']}")
        else:
            log("  ! 8446 is not answering yet; check `journalctl -u takserver` and /opt/tak/logs/takserver-api.log")
        log("=== DONE ===")
        return {"reset": True}
    finally:
        _release()


def create_client_cert(name, log):
    problems = preflight()
    if problems:
        raise CertError(" ".join(problems))
    name = validate_client_name(name)
    if (FILES_DIR / f"{name}.p12").exists():
        raise CertError(f"{name}.p12 already exists. Delete it first or pick another name.")
    _acquire()
    try:
        log(f"=== Creating client certificate {name} ===")
        if not makecert("client", name, log):
            raise CertError("makeCert.sh failed.")
        info = pem_info(read_pem(FILES_DIR / f"{name}.pem"))
        log(f"  {name}.p12 created, signed by {info['issuer_cn']}, valid until "
            + (f"{info['not_after']:%Y-%m-%d}" if info["not_after"] else "?"))
        return {"name": name}
    finally:
        _release()


# ---------------------------------------------------------------------------
# Files handed out
# ---------------------------------------------------------------------------

def downloadable(name, server_name=None):
    """Only certificates and keystores meant to leave the box. Never a private key, never a CA's
    signing keystore, never the root's material, never the server's own keystore or a Let's
    Encrypt keystore (both hold a private key)."""
    low = (name or "").lower()
    if not re.match(r"^[a-z0-9][a-z0-9._@-]*$", low):
        return False
    if low.endswith((".key", ".csr", ".crl", ".pk8", ".cfg", ".sh")) or "do-not-share" in low:
        return False
    if "-signing." in low or low.startswith("root-ca") or low.startswith("fed-") or "-le." in low:
        return False
    stem = low.rsplit(".", 1)[0]
    if stem in {SERVER_CERT_NAME, (server_name or server_cert_name()).lower()} and not low.endswith(".pem"):
        return False
    return low.endswith((".p12", ".pem", ".jks"))


def connection_package(server, port, trust_p12_path, trust_pass, client_p12_path=None, client_pass=None,
                       description=None):
    """An ATAK / iTAK connection data package, the same shape as TAK's make-connection-package.sh:
    MANIFEST/manifest.xml + config.pref + the truststore (+ a client .p12 for a full package).
    Without a client cert it enables certificate enrollment on first connect."""
    trust_name = os.path.basename(trust_p12_path)
    client_name = os.path.basename(client_p12_path) if client_p12_path else ""
    enroll = not client_p12_path
    desc = description or server
    pkg_uid = str(uuid.uuid4())
    pkg_name = re.sub(r"[^A-Za-z0-9._-]", "_", server) + ("-" + client_name[:-4] if client_name else "") + "-dp.zip"
    pref = ['<?xml version=\'1.0\' encoding=\'ASCII\' standalone=\'yes\'?>', "<preferences>",
            '  <preference version="1" name="cot_streams">',
            '    <entry key="count" class="class java.lang.Integer">1</entry>',
            f'    <entry key="description0" class="class java.lang.String">{_xml_escape(desc)}</entry>',
            '    <entry key="enabled0" class="class java.lang.Boolean">true</entry>',
            f'    <entry key="connectString0" class="class java.lang.String">{_xml_escape(server)}:{int(port)}:ssl</entry>',
            f'    <entry key="caLocation0" class="class java.lang.String">cert/{trust_name}</entry>',
            f'    <entry key="caPassword0" class="class java.lang.String">{_xml_escape(trust_pass)}</entry>']
    if client_name:
        pref += [f'    <entry key="certificateLocation0" class="class java.lang.String">cert/{client_name}</entry>',
                 f'    <entry key="clientPassword0" class="class java.lang.String">{_xml_escape(client_pass or trust_pass)}</entry>']
    if enroll:
        pref += ['    <entry key="enrollForCertificateWithTrust0" class="class java.lang.Boolean">true</entry>',
                 '    <entry key="useAuth0" class="class java.lang.Boolean">true</entry>',
                 '    <entry key="cacheCreds0" class="class java.lang.String">Cache credentials</entry>']
    pref += ["  </preference>", '  <preference version="1" name="com.atakmap.app_preferences">',
             '    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>',
             "  </preference>", "</preferences>", ""]
    manifest = ['<MissionPackageManifest version="2">', "  <Configuration>",
                f'    <Parameter name="uid" value="{pkg_uid}"/>',
                f'    <Parameter name="name" value="{pkg_name}"/>',
                '    <Parameter name="onReceiveDelete" value="true"/>',
                "  </Configuration>", "  <Contents>",
                '    <Content ignore="false" zipEntry="config.pref"/>',
                f'    <Content ignore="false" zipEntry="{trust_name}"/>']
    if client_name:
        manifest.append(f'    <Content ignore="false" zipEntry="{client_name}"/>')
    manifest += ["  </Contents>", "</MissionPackageManifest>", ""]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("MANIFEST/manifest.xml", "\n".join(manifest))
        z.writestr("config.pref", "\n".join(pref))
        z.write(trust_p12_path, trust_name)
        if client_p12_path:
            z.write(client_p12_path, client_name)
    return pkg_name, buf.getvalue()
