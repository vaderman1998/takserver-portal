#!/usr/bin/env python3
"""TAK Server Portal - zero-dependency admin panel: package upgrades and certificate management.

Built on the TAK Server Upgrade Portal. Everything that touches certificates lives in
takcerts.py; this file is the HTTP layer, the login, the upload / install actions and the job
runner whose output the terminal panel streams.
"""

import hmac
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import selfupdate
import snapshots
import takcerts
import terratak

HOST = "0.0.0.0"
PORT = int(os.environ.get("TAK_PORTAL_PORT", 9090))

LE_CERT_DIR = Path(os.environ.get("TAK_PORTAL_CERT_DIR", "/etc/letsencrypt/live/localhost"))
CERT_FILE = LE_CERT_DIR / "fullchain.pem"
KEY_FILE = LE_CERT_DIR / "privkey.pem"
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
STATE_FILE = BASE_DIR / "portal-state.json"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(mode=0o700, exist_ok=True)
LOG_KEEP = 60

ADMIN_USER = os.environ.get("TAK_PORTAL_USER", "admin")
ADMIN_PASS = os.environ.get("TAK_PORTAL_PASS", "takadmin")

TLS_ACTIVE = False


# ── Platform ───────────────────────────────────────────────────────────────

def detect_os_family():
    """Detect whether this is a Debian/Ubuntu or RHEL/Rocky/Alma system."""
    info = {"family": "unknown", "distro": "unknown", "pretty_name": "Unknown"}
    os_release = Path("/etc/os-release")
    if os_release.exists():
        fields = {}
        for line in os_release.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                fields[k] = v.strip('"')
        combo = (fields.get("ID", "") + fields.get("ID_LIKE", "")).lower()
        info["distro"] = fields.get("ID", "unknown")
        info["pretty_name"] = fields.get("PRETTY_NAME", info["distro"])
        if "debian" in combo or "ubuntu" in combo:
            info["family"] = "debian"
        elif "rhel" in combo or "fedora" in combo or "centos" in combo:
            info["family"] = "rhel"
    if info["family"] == "unknown":
        import shutil
        if shutil.which("apt-get"):
            info["family"] = "debian"
        elif shutil.which("dnf") or shutil.which("yum"):
            info["family"] = "rhel"
    return info


OS_INFO = detect_os_family()
PKG_EXT = ".rpm" if OS_INFO["family"] == "rhel" else ".deb"
PKG_MGR = "dnf" if OS_INFO["family"] == "rhel" else "apt"
INSTALL_CMD_TPL = (
    "sudo dnf install ./{filename} --setopt=clean_requirements_on_remove=false -y"
    if OS_INFO["family"] == "rhel"
    else "sudo apt install -y ./{filename}"
)


# ── Portal state (fqdn, last rotation) ─────────────────────────────────────

_state_lock = threading.Lock()


def load_state():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(update):
    with _state_lock:
        st = load_state()
        st.update(update)
        tmp = STATE_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(st, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_FILE)
        return st


def portal_fqdn():
    return (load_state().get("fqdn") or "").strip()


def default_server_host():
    """What devices should dial: installTAK records the enrollment package's endpoint (FQDN or
    public IP) in /opt/tak/takdatapackagedesc; otherwise this box's name."""
    try:
        lines = (takcerts.TAK_DIR / "takdatapackagedesc").read_text(errors="replace").splitlines()
        if len(lines) >= 2 and lines[1].strip():
            return lines[1].strip()
    except OSError:
        pass
    return socket.getfqdn()


# ── Sessions ───────────────────────────────────────────────────────────────

active_sessions = {}
SESSION_TTL = 3600


def verify_session(cookie_header):
    if not cookie_header:
        return False
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    if "session" not in cookie:
        return False
    sid = cookie["session"].value
    if sid in active_sessions and time.time() - active_sessions[sid] < SESSION_TTL:
        return True
    active_sessions.pop(sid, None)
    return False


def password_ok(pw):
    return hmac.compare_digest(str(pw or ""), ADMIN_PASS)


# ── Jobs: shell commands and Python jobs share one log store ───────────────

command_logs = {}


def _new_entry(command):
    cmd_id = uuid.uuid4().hex[:12]
    command_logs[cmd_id] = {"command": command, "status": "pending", "output": "", "exit_code": None}
    return cmd_id


def persist_log(cmd_id):
    """Write a finished job's output to logs/<time>-<label>.log (0600) so it survives a restart
    and can be pasted into a report. Keeps the newest LOG_KEEP files."""
    entry = command_logs.get(cmd_id)
    if not entry:
        return
    slug = re.sub(r"[^A-Za-z0-9]+", "-", entry["command"])[:48].strip("-") or "job"
    name = time.strftime("%Y%m%d-%H%M%S") + "-" + slug + ".log"
    try:
        path = LOG_DIR / name
        with open(path, "w") as f:
            f.write("# " + entry["command"] + "\n" + "# status: " + str(entry["status"]) + "  exit: "
                    + str(entry.get("exit_code")) + "\n" + "\n")
            f.write(entry["output"])
        os.chmod(path, 0o600)
        for old in sorted(LOG_DIR.glob("*.log"))[:-LOG_KEEP]:
            takcerts.unlink_quiet(old)
    except OSError:
        pass


def run_command(cmd_id, command, cwd=None):
    entry = command_logs[cmd_id]
    entry["status"] = "running"
    entry["start_time"] = time.time()
    try:
        proc = subprocess.Popen(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, bufsize=1, cwd=cwd,
        )
        entry["pid"] = proc.pid
        for line in proc.stdout:
            entry["output"] += line
        proc.wait()
        entry["exit_code"] = proc.returncode
        entry["status"] = "success" if proc.returncode == 0 else "error"
    except Exception as e:
        entry["output"] += f"\n[ERROR] {e}\n"
        entry["status"] = "error"
        entry["exit_code"] = -1
    entry["end_time"] = time.time()
    entry.pop("pid", None)
    if "tail -f" not in command:
        persist_log(cmd_id)


def run_job(cmd_id, fn, on_success=None):
    """Run fn(log) in this thread; its lines stream into the entry like a shell command's."""
    entry = command_logs[cmd_id]
    entry["status"] = "running"
    entry["start_time"] = time.time()

    def log(line):
        entry["output"] += str(line) + "\n"
    try:
        result = fn(log)
        entry["exit_code"] = 0
        entry["status"] = "success"
        if on_success:
            try:
                on_success(result)
            except Exception as e:  # noqa: BLE001
                log(f"[WARN] post-step failed: {e}")
    except takcerts.CertError as e:
        log(f"\n[REFUSED] {e}")
        entry["exit_code"] = 2
        entry["status"] = "error"
    except Exception as e:  # noqa: BLE001
        log(f"\n[ERROR] {type(e).__name__}: {e}")
        entry["exit_code"] = 1
        entry["status"] = "error"
    entry["end_time"] = time.time()
    persist_log(cmd_id)


def start_job(label, fn, on_success=None):
    cmd_id = _new_entry(label)
    threading.Thread(target=run_job, args=(cmd_id, fn, on_success), daemon=True).start()
    return cmd_id


def with_snapshot(slug, fn):
    """Save an automatic snapshot, then run fn(log). A snapshot that cannot be written stops the
    job before it touches anything."""
    def job(log):
        snap = snapshots.save(f"auto-before-{slug}-{time.strftime('%Y%m%d-%H%M%S')}", auto=True)
        log(f"Snapshot {snap['name']} saved ({max(1, snap['size'] // 1024)} KB). "
            "If anything goes wrong: Snapshots card > Restore.")
        return fn(log)
    return job


# ── Multipart (no cgi module) ──────────────────────────────────────────────

def parse_multipart(handler):
    content_type = handler.headers.get("Content-Type", "")
    match = re.search(r'boundary=([^\s;]+)', content_type)
    if not match:
        return None, None
    boundary = match.group(1).encode()
    length = int(handler.headers.get("Content-Length", 0))
    body = handler.rfile.read(length)
    parts = body.split(b"--" + boundary)
    for part in parts:
        if b"Content-Disposition" not in part:
            continue
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            continue
        header_block = part[:header_end].decode(errors="replace")
        file_data = part[header_end + 4:]
        if file_data.endswith(b"\r\n"):
            file_data = file_data[:-2]
        fname_match = re.search(r'filename="([^"]+)"', header_block)
        if fname_match:
            return fname_match.group(1), file_data
    return None, None


# ── HTTP handler ───────────────────────────────────────────────────────────

class TAKPortalHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    # -- responses --
    def _send(self, code, body, content_type="text/html", extra_headers=None):
        raw = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, code, data):
        self._send(code, json.dumps(data), "application/json")

    def _redirect(self, location, cookie=None):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _file(self, filepath, content_type):
        try:
            self._send(200, Path(filepath).read_bytes(), content_type)
        except FileNotFoundError:
            self._send(404, "Not Found")

    def _attachment(self, data, filename, content_type="application/octet-stream"):
        self._send(200, data, content_type, {"Content-Disposition": f'attachment; filename="{filename}"'})

    def _authed(self):
        return verify_session(self.headers.get("Cookie"))

    def _body_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return {}
        try:
            d = json.loads(self.rfile.read(length).decode())
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}

    # -- GET --
    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)

        if path == "/login":
            return self._file(TEMPLATE_DIR / "login.html", "text/html")

        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            if ".." in rel:
                return self._send(404, "Not Found")
            types = {".css": "text/css", ".js": "application/javascript",
                     ".png": "image/png", ".svg": "image/svg+xml"}
            return self._file(STATIC_DIR / rel, types.get(Path(rel).suffix, "application/octet-stream"))

        if path in ("/", "/dashboard"):
            if not self._authed():
                return self._redirect("/login")
            return self._file(TEMPLATE_DIR / "dashboard.html", "text/html")

        if path == "/logout":
            c = SimpleCookie()
            c.load(self.headers.get("Cookie", ""))
            if "session" in c:
                active_sessions.pop(c["session"].value, None)
            return self._redirect("/login", "session=; Max-Age=0; Path=/; HttpOnly")

        if not self._authed():
            return self._json(401, {"error": "unauthorized"})

        if path == "/api/uploads":
            files = []
            for f in sorted(UPLOAD_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                if f.suffix in (".deb", ".rpm"):
                    st = f.stat()
                    files.append({"name": f.name, "size": st.st_size, "mtime": st.st_mtime})
            return self._json(200, files)

        if path.startswith("/api/logs/"):
            cmd_id = path.split("/")[-1]
            entry = command_logs.get(cmd_id)
            if not entry:
                return self._json(404, {"error": "not found"})
            return self._json(200, {
                "id": cmd_id, "command": entry["command"],
                "status": entry["status"], "output": entry["output"],
                "exit_code": entry.get("exit_code"),
                "stoppable": "pid" in entry and entry["status"] == "running",
            })

        if path == "/api/status":
            try:
                r = subprocess.run(["systemctl", "is-active", "takserver"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, timeout=5)
                status = r.stdout.strip()
            except Exception:
                status = "unknown"
            return self._json(200, {"takserver_status": status, "listening_8089": takcerts.tak_listening(),
                                    "version": takcerts.installed_version()})

        if path == "/api/platform":
            return self._json(200, {
                "family": OS_INFO["family"], "distro": OS_INFO["distro"],
                "pretty_name": OS_INFO["pretty_name"], "pkg_ext": PKG_EXT, "pkg_mgr": PKG_MGR,
                "install_tpl": INSTALL_CMD_TPL.replace("{filename}", "{file}"),
            })

        if path == "/api/settings":
            return self._json(200, {"fqdn": portal_fqdn(), "default_host": default_server_host()})

        if path == "/api/terratak":
            try:
                cert_dir = str(LE_CERT_DIR) if CERT_FILE.exists() and KEY_FILE.exists() else ""
                return self._json(200, dict(terratak.status(terratak.settings_from(load_state()), portal_fqdn(), cert_dir), ok=True))
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

        if path == "/api/portal":
            try:
                return self._json(200, dict(selfupdate.info(selfupdate.settings_from(load_state())), ok=True))
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

        if path == "/api/certs/status":
            try:
                return self._json(200, takcerts.pki_status(portal_fqdn(), load_state().get("rotation") or {}))
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"error": f"{type(e).__name__}: {e}"})

        if path == "/api/certs/live":
            rows, err = takcerts.live_cert_rows()
            if rows is None:
                return self._json(200, {"ok": False, "error": err, "rows": [], "counts": {}})
            current = takcerts.pem_info(takcerts.read_pem(takcerts.FILES_DIR / "ca.pem"))["cn"]
            live_rows = [r for r in rows if r["live"]]
            return self._json(200, {"ok": True, "current_ca": current, "rows": live_rows,
                                    "counts": takcerts.live_counts_by_issuer(live_rows),
                                    "total": len(rows)})

        if path == "/api/snapshots":
            try:
                return self._json(200, {"ok": True, "dir": str(snapshots.SNAP_DIR), "items": snapshots.list_snapshots()})
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

        if path == "/api/snapshots/diff":
            try:
                d = snapshots.diff((query.get("name") or [""])[0])
                d["ok"] = True
                return self._json(200, d)
            except takcerts.CertError as e:
                return self._json(400, {"ok": False, "error": str(e)})
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

        if path.startswith("/api/certs/download/"):
            name = Path(path.split("/")[-1]).name
            if not takcerts.downloadable(name, takcerts.server_cert_name()):
                return self._json(403, {"error": "that file is not handed out by the portal"})
            target = takcerts.FILES_DIR / name
            if not target.is_file():
                return self._json(404, {"error": "not found"})
            return self._attachment(target.read_bytes(), name)

        if path == "/api/certs/package":
            try:
                cc = takcerts.coreconfig_text()
            except OSError:
                return self._json(400, {"error": "CoreConfig.xml not readable"})
            ts = takcerts.live_truststore_name(cc)
            if not ts:
                return self._json(400, {"error": "Could not tell which truststore TAK Server is using"})
            p12 = takcerts.FILES_DIR / (ts[:-4] + ".p12")
            if not p12.exists():
                return self._json(400, {"error": f"{p12.name} not found"})
            client = (query.get("client") or [""])[0]
            client_path = None
            if client:
                client = Path(client).name
                if client not in takcerts.client_cert_names():
                    return self._json(400, {"error": "unknown client certificate"})
                client_path = takcerts.FILES_DIR / f"{client}.p12"
            server = (query.get("server") or [""])[0] or portal_fqdn() or default_server_host()
            pw = takcerts.cert_password()
            name, data = takcerts.connection_package(server, 8089, str(p12), pw, str(client_path) if client_path else None, pw)
            return self._attachment(data, name, "application/zip")

        self._json(404, {"error": "not found"})

    # -- POST --
    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            params = parse_qs(body)
            user = params.get("username", [""])[0]
            pw = params.get("password", [""])[0]
            if hmac.compare_digest(user, ADMIN_USER) and password_ok(pw):
                sid = secrets.token_hex(32)
                active_sessions[sid] = time.time()
                flags = "; Secure" if TLS_ACTIVE else ""
                return self._redirect("/", f"session={sid}; Max-Age={SESSION_TTL}; Path=/; HttpOnly; SameSite=Strict{flags}")
            time.sleep(1)
            return self._redirect("/login?error=1")

        if not self._authed():
            return self._json(401, {"error": "unauthorized"})

        if path == "/api/upload":
            return self._upload()

        if path == "/api/run":
            body = self._body_json()
            action = body.get("action")
            filename = body.get("filename", "")
            allowed = {
                "install": INSTALL_CMD_TPL.format(filename=filename),
                "daemon-reload": "sudo systemctl daemon-reload",
                "restart": "sudo systemctl restart takserver",
                "tail-log": "tail -f /opt/tak/logs/takserver-messaging.log",
            }
            if action not in allowed:
                return self._json(400, {"error": f"unknown action: {action}"})
            if action == "install":
                if not filename or not (filename.endswith(".deb") or filename.endswith(".rpm")):
                    return self._json(400, {"error": "invalid filename"})
                if not (UPLOAD_DIR / filename).exists():
                    return self._json(400, {"error": "file not found in uploads"})
            command = allowed[action]
            cmd_id = _new_entry(command)
            cwd = str(UPLOAD_DIR) if action == "install" else None
            threading.Thread(target=run_command, args=(cmd_id, command, cwd), daemon=True).start()
            return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command})

        if path == "/api/delete":
            body = self._body_json()
            filename = Path(body.get("filename", "")).name
            if not filename or not (filename.endswith(".deb") or filename.endswith(".rpm")):
                return self._json(400, {"error": "invalid filename"})
            target = UPLOAD_DIR / filename
            if not target.exists():
                return self._json(404, {"error": "file not found"})
            target.unlink()
            return self._json(200, {"ok": True, "filename": filename})

        if path == "/api/stop":
            body = self._body_json()
            entry = command_logs.get(body.get("cmd_id", ""))
            if not entry:
                return self._json(404, {"error": "not found"})
            pid = entry.get("pid")
            if pid and entry["status"] == "running":
                try:
                    os.kill(pid, 15)
                except ProcessLookupError:
                    pass
                entry["status"] = "stopped"
                entry["output"] += "\n[Stopped by user]\n"
                return self._json(200, {"ok": True, "status": "stopped"})
            return self._json(400, {"error": "not running"})

        if path == "/api/settings":
            body = self._body_json()
            fqdn = str(body.get("fqdn", "")).strip().lower().rstrip(".")
            if fqdn and not takcerts.HOST_RE.match(fqdn):
                return self._json(400, {"error": "that is not a valid host name"})
            save_state({"fqdn": fqdn})
            return self._json(200, {"ok": True, "fqdn": fqdn})

        if path.startswith("/api/snapshots/"):
            return self._snapshots_post(path[len("/api/snapshots/"):])

        if path.startswith("/api/portal/"):
            return self._portal_post(path[len("/api/portal/"):])

        if path.startswith("/api/terratak/"):
            return self._terratak_post(path[len("/api/terratak/"):])

        # ── certificate jobs ───────────────────────────────────────────
        if path.startswith("/api/certs/"):
            return self._certs_post(path[len("/api/certs/"):])

        self._json(404, {"error": "not found"})

    def _upload(self):
        """A package (.deb / .rpm) or a TerraTAK image tarball (.tar). The browser sends the raw
        file body, streamed to disk in 1 MB pieces, so a 650 MB upload never sits in memory;
        multipart (curl -F) still works for small files."""
        query = parse_qs(urlparse(self.path).query)
        kind = (query.get("kind") or ["package"])[0]
        if kind == "terratak":
            dest_dir, exts, what = terratak.IMAGE_DIR, (".tar",), "image tarball (.tar)"
        else:
            kind, dest_dir, exts, what = "package", UPLOAD_DIR, (".deb", ".rpm"), PKG_EXT + " package"
        length = int(self.headers.get("Content-Length", 0) or 0)
        if self.headers.get("Content-Type", "").startswith("multipart/form-data"):
            filename, data = parse_multipart(self)
            if not filename:
                return self._json(400, {"error": "no file uploaded"})
            filename = Path(filename).name
            if not filename.endswith(exts):
                return self._json(400, {"error": f"only {what} files are allowed"})
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / filename
            dest.write_bytes(data)
        else:
            filename = Path((query.get("name") or [""])[0]).name
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,150}$", filename) or not filename.endswith(exts):
                self._drain(length)
                return self._json(400, {"error": f"only {what} files are allowed"})
            if length <= 0:
                return self._json(400, {"error": "empty upload"})
            dest_dir.mkdir(parents=True, exist_ok=True)
            free = shutil.disk_usage(str(dest_dir)).free
            if free < length + 200 * 1048576:
                self._drain(length)
                return self._json(507, {"error": f"not enough disk space: {free // 1048576} MB free, "
                                                 f"{length // 1048576} MB to receive plus headroom"})
            dest, tmp = dest_dir / filename, dest_dir / (filename + ".part")
            got = 0
            try:
                with open(str(tmp), "wb") as f:
                    while got < length:
                        chunk = self.rfile.read(min(1048576, length - got))
                        if not chunk:
                            break
                        f.write(chunk)
                        got += len(chunk)
            except OSError as e:
                takcerts.unlink_quiet(tmp)
                return self._json(500, {"error": f"could not write the file: {e}"})
            if got != length:
                takcerts.unlink_quiet(tmp)
                return self._json(400, {"error": f"upload cut short: {got} of {length} bytes arrived"})
            os.replace(str(tmp), str(dest))
        out = {"ok": True, "filename": filename, "size": dest.stat().st_size}
        if kind == "terratak":
            try:
                out["image"] = terratak.inspect_tar(dest)
            except takcerts.CertError as e:
                takcerts.unlink_quiet(dest)
                return self._json(400, {"error": str(e)})
        return self._json(200, out)

    def _drain(self, length, cap=64 * 1048576):
        """Read and discard a (small) request body so the error response gets through."""
        left = min(length, cap)
        while left > 0:
            chunk = self.rfile.read(min(1048576, left))
            if not chunk:
                break
            left -= len(chunk)

    def _terratak_post(self, op):
        """TerraTAK: start / stop / restart / logs / delete-file without the password; settings,
        install, remove, remove-data and install-engine with it."""
        body = self._body_json()
        st = terratak.settings_from(load_state())

        def job(label, fn):
            cmd_id = start_job(label, fn)
            return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})
        try:
            if op in ("start", "stop", "restart"):
                return job(f"terratak: {op}", lambda log: terratak.control(op, log))
            if op == "logs":
                return self._json(200, {"ok": True, "text": terratak.logs(int(body.get("lines") or 200))})
            if op == "delete-file":
                return self._json(200, {"ok": True, "name": terratak.delete_image(body.get("name"))})
            if not password_ok(body.get("password")):
                return self._json(403, {"error": "Incorrect portal password.", "need_password": True})
            if op == "settings":
                new = terratak.validate_settings(body, st)
                save_state({"terratak": new})
                return self._json(200, {"ok": True, "settings": terratak.public_settings(new),
                                        "note": "Settings take effect at the next install or upgrade, which recreates the container."})
            if op == "install":
                name = terratak.image_path(body.get("file")).name
                fqdn = portal_fqdn()
                cert_dir = str(LE_CERT_DIR) if CERT_FILE.exists() and KEY_FILE.exists() else ""
                return job(f"terratak: install {name}", lambda log: terratak.install(st, name, log, fqdn, cert_dir))
            if op == "remove":
                return job("terratak: remove container", lambda log: terratak.remove(log, with_data=False))
            if op == "remove-data":
                return job("terratak: remove container and data volume", lambda log: terratak.remove(log, with_data=True))
            if op == "install-engine":
                fam = OS_INFO["family"]
                return job("terratak: install docker", lambda log: terratak.install_engine(fam, log))
            return self._json(404, {"error": "unknown TerraTAK action"})
        except takcerts.CertError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _portal_post(self, op):
        """The portal's own update: check (streams, no password), settings and update (password)."""
        body = self._body_json()
        try:
            if op == "check":
                st = selfupdate.settings_from(load_state())
                cmd_id = start_job("portal: check for updates", lambda log: selfupdate.check(st, log))
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})
            if not password_ok(body.get("password")):
                return self._json(403, {"error": "Incorrect portal password.", "need_password": True})
            if op == "settings":
                repo = selfupdate.validate_repo(body.get("repo") or selfupdate.DEFAULT_REPO)
                branch = selfupdate.validate_branch(body.get("branch"))
                upd = {"update_repo": repo, "update_branch": branch}
                token = str(body.get("token") or "").strip()
                if token:
                    if not re.match(r"^[A-Za-z0-9_.~-]{8,255}$", token):
                        return self._json(400, {"error": "That does not look like an access token."})
                    upd["update_token"] = token
                elif body.get("clear_token"):
                    upd["update_token"] = ""
                save_state(upd)
                selfupdate.set_remote(repo)
                return self._json(200, {"ok": True, "repo": selfupdate.redact(repo), "branch": branch,
                                        "token_set": bool(selfupdate.settings_from(load_state())["token"])})
            if op == "update":
                st = selfupdate.settings_from(load_state())
                restart = body.get("restart", True) is not False
                skip = bool(body.get("skip_tests"))
                cmd_id = start_job("portal: update" + (" and restart" if restart else ""),
                                   lambda log: selfupdate.update(st, log, restart=restart, skip_tests=skip))
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})
            return self._json(404, {"error": "unknown portal action"})
        except takcerts.CertError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _snapshots_post(self, op):
        body = self._body_json()
        name = str(body.get("name") or "").strip()
        try:
            if op == "save":
                return self._json(200, {"ok": True, "item": snapshots.save(name or None)})
            if not password_ok(body.get("password")):
                return self._json(403, {"error": "Incorrect portal password.", "need_password": True})
            if op == "delete":
                snapshots.delete(name)
                return self._json(200, {"ok": True, "name": name})
            if op == "restore":
                name = snapshots.validate_name(name)
                if not snapshots.path_for(name).exists():
                    return self._json(404, {"error": f"Snapshot '{name}' not found."})

                def done(_result):
                    save_state({"rotation": {}})
                cmd_id = start_job(f"portal: restore snapshot {name}", lambda log: snapshots.restore(name, log), done)
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})
            return self._json(404, {"error": "unknown snapshot action"})
        except takcerts.CertError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _certs_post(self, op):
        body = self._body_json()
        fqdn = portal_fqdn()

        def gated():
            if not password_ok(body.get("password")):
                self._json(403, {"error": "Incorrect portal password.", "need_password": True})
                return False
            return True

        try:
            if op == "rotate-intca":
                if not gated():
                    return
                name = takcerts.validate_ca_name(body.get("new_name"), "New CA name")
                days = body.get("days") or takcerts.INTERMEDIATE_DEFAULT_DAYS
                new_pw = str(body.get("new_password") or "").strip()
                if new_pw and (len(new_pw) < 6 or any(c in new_pw for c in "\"'\\ \n\t")):
                    return self._json(400, {"error": "The new certificate password needs 6+ characters and no quotes, spaces or backslashes."})

                reissue = bool(body.get("reissue_clients", True))

                def job(log):
                    return takcerts.rotate_intermediate(name, log, days=days, new_password=new_pw, fqdn=fqdn,
                                                        reissue_clients=reissue)

                def done(result):
                    save_state({"rotation": result})
                cmd_id = start_job(f"portal: rotate intermediate CA -> {name}", with_snapshot("rotate", job), done)
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})

            if op == "revoke":
                if not gated():
                    return
                alias = str(body.get("alias") or "").strip()
                if not alias or len(alias) > 128:
                    return self._json(400, {"error": "alias is required"})

                def job(log):
                    return takcerts.revoke_old_ca(alias, log, fqdn=fqdn)

                def done(result):
                    rot = load_state().get("rotation") or {}
                    if rot and (rot.get("old", "").lower() in (alias.lower(), (result.get("cn") or "").lower())):
                        save_state({"rotation": {}})
                cmd_id = start_job(f"portal: revoke old CA {alias}", with_snapshot("revoke", job), done)
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})

            if op == "rotate-root":
                if not gated():
                    return
                new_root = takcerts.validate_ca_name(body.get("new_root"), "New root CA name")
                new_int = takcerts.validate_ca_name(body.get("new_int"), "New intermediate CA name")
                new_pw = str(body.get("new_password") or "").strip()

                def job(log):
                    return takcerts.rotate_root(new_root, new_int, log, root_days=body.get("root_days") or takcerts.ROOT_DEFAULT_DAYS,
                                                int_days=body.get("int_days") or takcerts.INTERMEDIATE_DEFAULT_DAYS,
                                                new_password=new_pw, fqdn=fqdn)

                def done(_result):
                    save_state({"rotation": {}})
                cmd_id = start_job(f"portal: rotate ROOT CA -> {new_root} / {new_int}", with_snapshot("root", job), done)
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})

            if op == "signer":
                if not gated():
                    return
                signer = body.get("signer")
                if signer not in takcerts.SIGNERS:
                    return self._json(400, {"error": "signer must be root or intermediate"})
                cmd_id = start_job(f"portal: sign the server certificate with the {signer} CA",
                                   with_snapshot("signer", lambda log: takcerts.switch_signer(signer, log, fqdn=fqdn)))
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})

            if op == "reissue-server":
                if not gated():
                    return
                cmd_id = start_job("portal: reissue the server certificate with this server's names",
                                   with_snapshot("reissue", lambda log: takcerts.reissue_server(log, fqdn=fqdn)))
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})

            if op == "reset-8446":
                if not gated():
                    return
                cmd_id = start_job("portal: put 8446 back on TAK Server's own certificate",
                                   with_snapshot("reset-8446", lambda log: takcerts.reset_connector_8446(log)))
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})

            if op == "client":
                name = takcerts.validate_client_name(body.get("name"))
                cmd_id = start_job(f"portal: create client certificate {name}",
                                   lambda log: takcerts.create_client_cert(name, log))
                return self._json(200, {"ok": True, "cmd_id": cmd_id, "command": command_logs[cmd_id]["command"]})

            return self._json(404, {"error": "unknown certificate action"})
        except takcerts.CertError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    global TLS_ACTIVE
    if hasattr(http.server, "ThreadingHTTPServer"):
        server_cls = http.server.ThreadingHTTPServer
    else:
        import socketserver

        class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
        server_cls = ThreadingHTTPServer
    server = server_cls((HOST, PORT), TAKPortalHandler)

    if CERT_FILE.exists() and KEY_FILE.exists():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        else:                                   # Python 3.6 (RHEL 8)
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        TLS_ACTIVE = True
        proto = "https"
    else:
        proto = "http"
        print("  [WARN] No SSL certs found, running plain HTTP")

    if ADMIN_PASS == "takadmin":
        print("  [WARN] The portal password is still the default; set TAK_PORTAL_PASS in the service unit.")
    print("=" * 54)
    print("  TAK Server Portal")
    print(f"  Running on {proto}://{HOST}:{PORT}")
    print(f"  Login: {ADMIN_USER}")
    print("=" * 54)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
