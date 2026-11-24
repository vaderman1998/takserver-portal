#!/usr/bin/env python3
"""TerraTAK (TAK Product Center's tile server) as a container on this box.

TAK.gov ships TerraTAK as a `docker save` tarball per CPU architecture (terratak-<ver>-amd64.tar,
-arm64.tar). Its own documentation (doc/markdown/index.md inside the image) says: load it with
`docker image load`, run it with `docker run -d --name terratak -p 8080:8080 -v terratak-data:/opt/terratak
terratak:<ver>`; it has no login of its own and takes Helidon YAML for security; tuning is by
environment variables. This module does exactly that, with the upgrade (replace the container,
keep the volume), a basic-auth security file, the firewall and a health wait. docker or podman.
Standard library only, Python 3.6+.
"""

import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import takcerts

IMAGE_DIR = Path(os.environ.get("TAK_PORTAL_IMAGES", str(Path(__file__).resolve().parent / "uploads" / "terratak")))
CONFIG_DIR = Path(os.environ.get("TERRATAK_CONFIG_DIR", "/opt/terratak-config"))
CONTAINER = "terratak"
VOLUME = "terratak-data"
IMAGE_REPO = "terratak"
INNER_PORT = 8080
HEALTH_PATH = "/observe/health"
DEFAULTS = {"port": 8080, "max_memory": "256M", "t3_memory": "512M", "map_center": "",
            "auth_user": "", "auth_pass": "", "firewall": True, "tls": True}
HOOK_DIR = Path("/etc/letsencrypt/renewal-hooks/deploy")
MEM_RE = re.compile(r"^\d{1,6}[MmGg]$")
CENTER_RE = re.compile(r"^-?\d{1,3}(\.\d+)?,-?\d{1,2}(\.\d+)?(,\d{1,2})?$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.tar$")


class TerraTAKError(takcerts.CertError):
    pass


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _run(argv, timeout=60, input_text=None):
    try:
        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                           timeout=timeout, input=input_text)
        return r.returncode, (r.stdout or "").rstrip()
    except subprocess.TimeoutExpired:
        return 124, "timed out after %ds: %s" % (timeout, " ".join(argv[:3]))
    except OSError as e:
        return 127, str(e)


def _stream(argv, log, timeout=1800):
    """Run argv and hand every output line to log as it arrives; (rc, last 40 lines)."""
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
    except OSError as e:
        log("  " + str(e))
        return 127, [str(e)]
    tail = []
    start = time.time()
    for line in p.stdout:
        line = line.rstrip("\r\n")
        if line:
            log("  " + line)
            tail.append(line)
            del tail[:-40]
        if time.time() - start > timeout:
            p.kill()
            log("  (killed after %ds)" % timeout)
            break
    p.wait()
    return p.returncode, tail


def engine():
    """The container engine's binary: docker first, podman second, '' when neither is there."""
    for name in ("docker", "podman"):
        p = shutil.which(name)
        if p:
            return p
    return ""


def engine_name(exe=None):
    return os.path.splitext(os.path.basename(exe or engine() or ""))[0].lower()


def host_arch():
    m = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)


def daemon_ok(exe):
    rc, _ = _run([exe, "info"], timeout=20)
    return rc == 0


def engine_version(exe):
    rc, out = _run([exe, "--version"], timeout=10)
    return out.splitlines()[0].strip() if rc == 0 and out else ""


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def settings_from(state):
    s = dict(DEFAULTS)
    s.update({k: v for k, v in (state.get("terratak") or {}).items() if k in DEFAULTS})
    return s


def validate_settings(body, current):
    """body (from the browser) over the current settings; returns the new dict or raises."""
    s = dict(current)
    try:
        port = int(str(body.get("port", s["port"])).strip() or 8080)
    except ValueError:
        raise TerraTAKError("Port must be a number.")
    if not 1 <= port <= 65535:
        raise TerraTAKError("Port must be between 1 and 65535.")
    s["port"] = port
    for key, label in (("max_memory", "Server memory"), ("t3_memory", "Tiling memory")):
        v = str(body.get(key, s[key])).strip().upper() or DEFAULTS[key]
        if not MEM_RE.match(v):
            raise TerraTAKError("%s: a number with M or G, e.g. 512M or 2G." % label)
        s[key] = v
    center = str(body.get("map_center", s["map_center"])).strip().replace(" ", "")
    if center and not CENTER_RE.match(center):
        raise TerraTAKError("Map center: longitude,latitude[,zoom], e.g. -77.03,38.89,10")
    s["map_center"] = center
    user = str(body.get("auth_user", s["auth_user"])).strip()
    if user and not USER_RE.match(user):
        raise TerraTAKError("Login name: letters, numbers, dots, hyphens and underscores.")
    s["auth_user"] = user
    if "auth_pass" in body and str(body.get("auth_pass") or ""):
        pw = str(body["auth_pass"])
        if len(pw) < 6 or len(pw) > 128 or "\n" in pw:
            raise TerraTAKError("Password: 6 to 128 characters.")
        s["auth_pass"] = pw
    if body.get("clear_auth"):
        s["auth_user"], s["auth_pass"] = "", ""
    if s["auth_user"] and not s["auth_pass"]:
        raise TerraTAKError("Set a password for the login name (or clear both).")
    if "firewall" in body:
        s["firewall"] = bool(body["firewall"])
    if "tls" in body:
        s["tls"] = bool(body["tls"])
    return s


def public_settings(s):
    d = {k: v for k, v in s.items() if k != "auth_pass"}
    d["auth_set"] = bool(s.get("auth_user") and s.get("auth_pass"))
    return d


def security_yaml(user, password):
    """Helidon security: everyone signs in, only this user may change data, the health endpoint
    stays open so the image's own HEALTHCHECK keeps working."""
    return "\n".join([
        "security:",
        "  providers:",
        "    - http-basic-auth:",
        '        realm: "terratak"',
        "        users:",
        "          - login: %s" % json.dumps(user),
        "            password: %s" % json.dumps(password),
        '            roles: ["user", "admin"]',
        "  web-server:",
        "    defaults:",
        "      authenticate: true",
        "    paths:",
        '      - path: "/observe/*"',
        "        authenticate: false",
        '      - path: "/*"',
        '        methods: ["put", "post", "patch", "delete"]',
        '        roles-allowed: ["admin"]',
        "",
    ])


# Helidon 4 (TerraTAK 0.8.x ships 4.5.7): server.tls.private-key.pem.{key,cert-chain}.resource.path
# takes a PKCS#8 key and a chain in PEM, which is exactly what certbot writes.
TLS_YAML = """server:
  tls:
    private-key:
      pem:
        key:
          resource:
            path: "/config/tls/privkey.pem"
        cert-chain:
          resource:
            path: "/config/tls/fullchain.pem"
"""


def tls_source(cert_dir):
    """The certificate pair the portal itself serves (Let's Encrypt live dir or any PEM pair):
    {'dir', 'fullchain', 'privkey', 'name'}, or None when it is not there."""
    if not cert_dir:
        return None
    d = Path(str(cert_dir))
    full, key = d / "fullchain.pem", d / "privkey.pem"
    if not (full.is_file() and key.is_file()):
        return None
    return {"dir": str(d), "fullchain": str(full), "privkey": str(key), "name": d.name or str(d)}


def renew_hook(cert_dir, exe):
    """certbot deploy hook: refresh TerraTAK's copy of the pair and restart it after a renewal."""
    return "\n".join([
        "#!/bin/sh",
        "# Written by TAK Server Portal: TerraTAK serves a copy of this certificate.",
        "# certbot runs this after a successful renewal; refresh the copy, restart the container.",
        'SRC="%s"' % cert_dir,
        'DST="%s"' % (CONFIG_DIR / "tls"),
        '[ -z "${RENEWED_LINEAGE:-}" ] || [ "$RENEWED_LINEAGE" = "$SRC" ] || exit 0',
        '[ -f "$SRC/fullchain.pem" ] && [ -f "$SRC/privkey.pem" ] || exit 0',
        'cp -L "$SRC/fullchain.pem" "$DST/fullchain.pem" && cp -L "$SRC/privkey.pem" "$DST/privkey.pem" && chmod 600 "$DST"/*.pem',
        '"%s" restart %s >/dev/null 2>&1 || true' % (exe, CONTAINER),
        "",
    ])


def _write_tls(src, exe, log):
    """Copy the pair into the config mount (the container cannot follow Let's Encrypt's symlinks
    into archive/), write Helidon's TLS file, leave certbot a deploy hook."""
    tdir = CONFIG_DIR / "tls"
    tdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for key in ("fullchain", "privkey"):
        dst = tdir / (key + ".pem")
        shutil.copyfile(src[key], str(dst))
        os.chmod(str(dst), 0o600)
    with open(str(CONFIG_DIR / "tls.yaml"), "w") as f:
        f.write(TLS_YAML)
    os.chmod(str(CONFIG_DIR / "tls.yaml"), 0o644)
    log("  HTTPS with the certificate from %s (copied to %s)" % (src["dir"], tdir))
    if HOOK_DIR.is_dir():
        hook = HOOK_DIR / "terratak-tls.sh"
        with open(str(hook), "w") as f:
            f.write(renew_hook(src["dir"], exe))
        os.chmod(str(hook), 0o755)
        log("  certbot deploy hook %s refreshes the copy and restarts TerraTAK after each renewal" % hook)
    else:
        log("  no certbot deploy-hook directory (%s): after a renewal, reinstall TerraTAK to pick the new certificate up" % HOOK_DIR)


# ---------------------------------------------------------------------------
# Image tarballs
# ---------------------------------------------------------------------------

def inspect_tar(path):
    """{'name': 'terratak:0.8.6', 'version', 'arch', 'created', 'size'} from a docker-save tarball.
    Reads only the manifest and the image config (tar headers are skipped over, not the layers)."""
    path = Path(path)
    try:
        with tarfile.open(str(path)) as tar:
            try:
                manifest = json.loads(tar.extractfile(tar.getmember("manifest.json")).read().decode())
            except KeyError:
                raise TerraTAKError("%s is not a container image archive (no manifest.json)." % path.name)
            entry = manifest[0] if isinstance(manifest, list) and manifest else {}
            tags = entry.get("RepoTags") or []
            cfg_name = entry.get("Config") or ""
            cfg = None
            for cand in (cfg_name, "blobs/" + cfg_name.replace(":", "/")):
                try:
                    cfg = json.loads(tar.extractfile(tar.getmember(cand)).read().decode())
                    break
                except KeyError:
                    continue
    except (tarfile.TarError, OSError, ValueError) as e:
        raise TerraTAKError("%s could not be read as a tar archive: %s" % (path.name, e))
    name = next((t for t in tags if t.split(":")[0].endswith(IMAGE_REPO)), tags[0] if tags else "")
    if not name or not name.split(":")[0].endswith(IMAGE_REPO):
        raise TerraTAKError("%s holds the image %s, not a TerraTAK image." % (path.name, ", ".join(tags) or "(untagged)"))
    arch = (cfg or {}).get("architecture", "")
    created = ((cfg or {}).get("created") or "")[:10]
    return {"name": name, "version": name.split(":", 1)[1] if ":" in name else "", "arch": arch,
            "created": created, "size": path.stat().st_size}


def list_images():
    """Uploaded tarballs, newest first, each with what inspect_tar found (or its error)."""
    if not IMAGE_DIR.is_dir():
        return []
    items = []
    for p in sorted(IMAGE_DIR.glob("*.tar"), key=lambda q: q.stat().st_mtime, reverse=True):
        row = {"file": p.name, "size": p.stat().st_size, "mtime": int(p.stat().st_mtime), "name": "", "version": "",
               "arch": "", "created": "", "error": ""}
        try:
            row.update(inspect_tar(p))
        except takcerts.CertError as e:
            row["error"] = str(e)
        items.append(row)
    return items


def image_path(name):
    name = Path(str(name or "")).name
    if not NAME_RE.match(name):
        raise TerraTAKError("That is not an uploaded image file.")
    p = IMAGE_DIR / name
    if not p.is_file():
        raise TerraTAKError("%s is not in %s." % (name, IMAGE_DIR))
    return p


def delete_image(name):
    p = image_path(name)
    p.unlink()
    return p.name


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def container_state(exe):
    """None when there is no container, else status / running / image / health / started / ports."""
    rc, out = _run([exe, "inspect", "--type", "container", "--format",
                    "{{.State.Status}}\t{{.State.Running}}\t{{.Config.Image}}\t"
                    "{{if .State.Health}}{{.State.Health.Status}}{{end}}\t{{.State.StartedAt}}\t"
                    "{{range .Config.Env}}{{.}};{{end}}", CONTAINER], timeout=20)
    if rc != 0 or "\t" not in out:
        return None
    parts = (out.splitlines()[0] + "\t\t\t\t\t").split("\t")
    st = {"status": parts[0], "running": parts[1] == "true", "image": parts[2], "health": parts[3],
          "started": parts[4][:19].replace("T", " "), "ports": "", "tls": "tls.yaml" in parts[5]}
    rc, out = _run([exe, "port", CONTAINER, str(INNER_PORT)], timeout=20)
    if rc == 0 and out:
        st["ports"] = ", ".join(l.strip() for l in out.splitlines() if l.strip())
    return st


def loaded_images(exe):
    rc, out = _run([exe, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}", IMAGE_REPO], timeout=30)
    rows = []
    if rc == 0:
        for line in out.splitlines():
            bits = line.split("\t")
            if len(bits) >= 3 and bits[0].startswith(IMAGE_REPO + ":"):
                rows.append({"name": bits[0], "id": bits[1], "size": bits[2]})
    return rows


def status(settings, fqdn="", cert_dir=""):
    """Everything the TerraTAK card shows, in one call."""
    exe = engine()
    src = tls_source(cert_dir)
    st = {"engine": engine_name(exe), "engine_path": exe, "engine_version": "", "daemon": False,
          "arch": host_arch(), "images": [], "container": None, "files": list_images(),
          "settings": public_settings(settings), "url": "", "problems": [],
          "tls_available": src["name"] if src else ""}
    if not exe:
        st["problems"].append("No container engine on this server. Install Docker (button below) or podman.")
        return st
    st["engine_version"] = engine_version(exe)
    st["daemon"] = daemon_ok(exe)
    if not st["daemon"]:
        st["problems"].append("%s is installed but its service is not running: systemctl enable --now %s"
                              % (st["engine"], st["engine"]))
        return st
    st["images"] = loaded_images(exe)
    st["container"] = container_state(exe)
    host = fqdn or socket.getfqdn()
    tls = st["container"]["tls"] if st["container"] else bool(src and settings.get("tls", True))
    st["url"] = "%s://%s:%d/" % ("https" if tls else "http", host, int(settings["port"]))
    return st


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def _need_engine():
    exe = engine()
    if not exe:
        raise TerraTAKError("No container engine on this server. Use 'Install Docker' first.")
    if not daemon_ok(exe):
        raise TerraTAKError("%s is installed but not running: systemctl enable --now %s" % (engine_name(exe), engine_name(exe)))
    return exe


def wait_healthy(port, log, timeout=150, tls=False):
    """Poll the health endpoint until it answers (200, or 401 when basic auth guards it)."""
    url = "%s://127.0.0.1:%d%s" % ("https" if tls else "http", port, HEALTH_PATH)
    ctx = None
    if tls:                                     # the certificate names the host, we dial the loopback
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    start = time.time()
    last = 0
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=3, context=ctx) as r:
                if r.status in (200, 204):
                    return True
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        waited = int(time.time() - start)
        if waited - last >= 15:
            last = waited
            log("  still starting (%ds)..." % waited)
        time.sleep(2)
    return False


def _firewall_open(port, log):
    if shutil.which("ufw"):
        rc, out = _run(["ufw", "status"], timeout=20)
        if rc == 0 and "Status: active" in out:
            if ("%d/tcp" % port) in out:
                log("  ufw: %d/tcp already open" % port)
            else:
                rc, out = _run(["ufw", "allow", "%d/tcp" % port, "comment", "TerraTAK"], timeout=30)
                log("  ufw: %s" % (out.strip().splitlines()[-1] if out.strip() else ("rc=%d" % rc)))
            return
    if shutil.which("firewall-cmd"):
        rc, _ = _run(["firewall-cmd", "--state"], timeout=20)
        if rc == 0:
            rc, out = _run(["firewall-cmd", "--query-port=%d/tcp" % port], timeout=20)
            if rc == 0:
                log("  firewalld: %d/tcp already open" % port)
            else:
                _run(["firewall-cmd", "--permanent", "--add-port=%d/tcp" % port], timeout=30)
                rc, out = _run(["firewall-cmd", "--reload"], timeout=60)
                log("  firewalld: opened %d/tcp (%s)" % (port, out.strip() or "rc=%d" % rc))
            return
    log("  no active ufw / firewalld found; nothing to open")


def run_args(exe, image, s, tls=False):
    """The docker run argv for the saved settings (no secrets in it: the password lives in the
    security file, mounted read-only)."""
    argv = [exe, "run", "-d", "--name", CONTAINER, "--restart", "unless-stopped",
            "-p", "%d:%d" % (int(s["port"]), INNER_PORT), "-v", "%s:/opt/terratak" % VOLUME,
            "-e", "TERRATAK_MAX_MEMORY=" + s["max_memory"], "-e", "T3_MAX_MEMORY=" + s["t3_memory"]]
    if s.get("map_center"):
        argv += ["-e", "TERRATAK_MAP_CENTER=" + s["map_center"]]
    cfg = []
    if s.get("auth_user") and s.get("auth_pass"):
        cfg.append("/config/security.yaml")
    if tls:
        cfg.append("/config/tls.yaml")
        # the image's own HEALTHCHECK speaks plain http; with TLS on it would say "unhealthy" forever
        argv += ["--health-cmd", "curl -fk https://localhost:%d%s || exit 1" % (INNER_PORT, HEALTH_PATH)]
    if cfg:
        argv += ["-v", "%s:/config:ro" % CONFIG_DIR, "-e", "TERRATAK_SERVER_CONFIG_FILES=" + ":".join(cfg)]
    if engine_name(exe) == "podman":
        argv.insert(2, "--label")
        argv.insert(3, "io.containers.autoupdate=disabled")
    argv.append(image)
    return argv


def _write_security(s, log):
    CONFIG_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    p = CONFIG_DIR / "security.yaml"
    with open(str(p), "w") as f:
        f.write(security_yaml(s["auth_user"], s["auth_pass"]))
    os.chmod(str(p), 0o644)              # the container reads it as its own user; the directory is root's
    log("  login required: user '%s' (security file %s)" % (s["auth_user"], p))


def install(settings, file_name, log, fqdn="", cert_dir=""):
    """Load the tarball, replace the container (data volume kept), run, open the firewall, wait.
    cert_dir: where the portal's own certificate pair lives; with the tls setting on, TerraTAK
    serves it too."""
    exe = _need_engine()
    eng = engine_name(exe)
    takcerts._acquire()
    try:
        tar = image_path(file_name)
        log("=== TerraTAK: install %s with %s ===" % (tar.name, eng))
        info = inspect_tar(tar)
        arch = host_arch()
        if info["arch"] and info["arch"] != arch:
            raise TerraTAKError("%s is built for %s; this server is %s. Upload the %s tarball."
                                % (tar.name, info["arch"], arch, arch))
        log("Step 1/5: Loading image %s (%s, built %s, %d MB)..."
            % (info["name"], info["arch"] or "?", info["created"] or "?", info["size"] // 1048576))
        rc, tail = _stream([exe, "load", "-i", str(tar)], log, timeout=1800)
        if rc != 0:
            raise TerraTAKError("%s load failed (rc %d): %s" % (eng, rc, " / ".join(tail[-3:])))
        image = info["name"]
        for line in tail:
            m = re.search(r"Loaded image(?:\(s\))?:\s*(\S+)", line)
            if m:
                image = m.group(1)
        log("Step 2/5: Container")
        current = container_state(exe)
        if current:
            log("  replacing the existing container (%s, %s); the data volume %s is kept" % (current["image"], current["status"], VOLUME))
            rc, out = _run([exe, "rm", "-f", CONTAINER], timeout=120)
            if rc != 0:
                raise TerraTAKError("%s rm -f %s: %s" % (eng, CONTAINER, out[-200:]))
        else:
            log("  no container yet")
        port = int(settings["port"])
        if takcerts.tak_listening(port):
            raise TerraTAKError("Port %d is already in use on this server; pick another port in the settings." % port)
        if settings.get("auth_user") and settings.get("auth_pass"):
            _write_security(settings, log)
        else:
            log("  no login configured: anyone who can reach port %d can use and change TerraTAK" % port)
        src = tls_source(cert_dir) if settings.get("tls", True) else None
        if src:
            _write_tls(src, exe, log)
        elif settings.get("tls", True):
            log("  no certificate pair in %s: TerraTAK stays plain HTTP" % (cert_dir or "the portal's certificate directory"))
        else:
            log("  HTTPS switched off in the settings: plain HTTP")
        argv = run_args(exe, image, settings, tls=bool(src))
        log("Step 3/5: " + " ".join(argv))
        rc, out = _run(argv, timeout=180)
        if rc != 0:
            raise TerraTAKError("%s run failed: %s" % (eng, out.strip()[-400:]))
        log("  container id %s" % out.strip()[:12])
        log("Step 4/5: Firewall")
        if settings.get("firewall", True):
            _firewall_open(port, log)
        else:
            log("  left alone at your request")
        log("Step 5/5: Waiting for TerraTAK to answer on port %d..." % port)
        if not wait_healthy(port, log, tls=bool(src)):
            rc, out = _run([exe, "logs", "--tail", "40", CONTAINER], timeout=30)
            for line in out.splitlines():
                log("  | " + line)
            raise TerraTAKError("TerraTAK did not answer within the wait; its last log lines are above. The container is left in place.")
        host = fqdn or socket.getfqdn()
        url = "%s://%s:%d/" % ("https" if src else "http", host, port)
        log("=== TERRATAK RUNNING: %s ===" % image)
        log("  Web UI:   %s" % url)
        log("  REST API: %sopenapi/ui/index.html" % url)
        log("  Tiles reach ATAK through the TAK JSON pointer or QR code TerraTAK shows for each tileset.")
        if settings.get("auth_user") and settings.get("auth_pass"):
            log("  Sign in as '%s'. Devices streaming tiles need the same login." % settings["auth_user"])
        if src:
            log("  HTTPS with the %s certificate; it follows certbot renewals through the deploy hook." % src["name"])
        else:
            log("  Traffic is plain HTTP. A browser that has visited TAK Server's 8443 on this host name will refuse")
            log("  it (HSTS); use the IP address, or get a Let's Encrypt certificate onto the box and reinstall.")
        return {"image": image, "url": url}
    finally:
        takcerts._release()


def control(action, log):
    """start / stop / restart the container."""
    if action not in ("start", "stop", "restart"):
        raise TerraTAKError("Unknown action.")
    exe = _need_engine()
    if not container_state(exe):
        raise TerraTAKError("There is no TerraTAK container yet; install an image first.")
    log("=== TerraTAK: %s ===" % action)
    rc, out = _run([exe, action, CONTAINER], timeout=180)
    if rc != 0:
        raise TerraTAKError("%s %s: %s" % (engine_name(exe), action, out.strip()[-300:]))
    st = container_state(exe) or {}
    log("  %s: %s" % (CONTAINER, st.get("status", "?")))
    return st


def remove(log, with_data=False):
    """Remove the container; with_data also deletes the volume (every tileset)."""
    exe = _need_engine()
    takcerts._acquire()
    try:
        log("=== TerraTAK: remove container%s ===" % (" and data" if with_data else ""))
        if container_state(exe):
            rc, out = _run([exe, "rm", "-f", CONTAINER], timeout=120)
            log("  container removed" if rc == 0 else "  rm: " + out.strip()[-200:])
            if rc != 0:
                raise TerraTAKError("Could not remove the container.")
        else:
            log("  no container")
        if with_data:
            rc, out = _run([exe, "volume", "rm", VOLUME], timeout=120)
            if rc == 0:
                log("  volume %s deleted" % VOLUME)
            elif "no such volume" in out.lower():
                log("  no volume %s" % VOLUME)
            else:
                raise TerraTAKError("volume rm: " + out.strip()[-200:])
        else:
            log("  data volume %s kept; reinstalling an image brings everything back" % VOLUME)
        return {"removed": True}
    finally:
        takcerts._release()


def logs(lines=200):
    exe = engine()
    if not exe:
        raise TerraTAKError("No container engine.")
    rc, out = _run([exe, "logs", "--tail", str(int(lines)), CONTAINER], timeout=30)
    if rc != 0:
        raise TerraTAKError(out.strip()[-300:] or "no container")
    return out


def install_engine(family, log):
    """Docker from the distribution (Debian/Ubuntu) or Docker CE's own repository (RHEL family)."""
    if engine():
        raise TerraTAKError("A container engine is already installed (%s)." % engine())
    takcerts._acquire()
    try:
        log("=== Installing Docker ===")
        if family == "debian":
            steps = [["apt-get", "update", "-qq"], ["apt-get", "install", "-y", "-qq", "docker.io"]]
        elif family == "rhel":
            steps = [["dnf", "-y", "-q", "install", "dnf-plugins-core"],
                     ["dnf", "config-manager", "--add-repo", "https://download.docker.com/linux/centos/docker-ce.repo"],
                     ["dnf", "-y", "install", "docker-ce", "docker-ce-cli", "containerd.io"]]
        else:
            raise TerraTAKError("Unknown OS family; install Docker or podman by hand.")
        steps.append(["systemctl", "enable", "--now", "docker"])
        for argv in steps:
            log("$ " + " ".join(argv))
            rc, tail = _stream(argv, log, timeout=1800)
            if rc != 0:
                raise TerraTAKError("'%s' failed (rc %d)." % (" ".join(argv[:3]), rc))
        exe = engine()
        log("=== Docker installed: %s (%s) ===" % (exe, engine_version(exe) if exe else "?"))
        return {"engine": exe}
    finally:
        takcerts._release()
