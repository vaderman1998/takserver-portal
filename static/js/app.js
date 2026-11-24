/* TAK Server Portal – Frontend Logic (upgrade + certificates) */

(function () {
  "use strict";

  let selectedFile = null;
  let pollingTimer = null;
  let lastOutputLen = 0;
  let activeCmdId = null;
  let cmdFinished = false;
  let activeIsCertJob = false;
  let platform = { pkg_ext: ".deb", pkg_mgr: "apt", family: "debian", install_tpl: "sudo apt install -y ./{file}" };
  let certs = null;        // last /api/certs/status
  let liveRows = null;     // last /api/certs/live
  let passShown = false;
  let activeIsPortalUpdate = false;   // the running job is the portal's own check or update
  let portalRestartPending = false;   // a successful update restarts the portal; sessions do not survive that
  let portalInfo = null;              // last /api/portal
  let tt = null;                      // last /api/terratak

  function $(sel) { return document.querySelector(sel); }
  function $$(sel) { return document.querySelectorAll(sel); }

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
  }

  function timeAgo(ts) {
    const diff = (Date.now() / 1000) - ts;
    if (diff < 60) return "just now";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return new Date(ts * 1000).toLocaleDateString();
  }

  function daysText(d) {
    if (d == null) return "";
    if (d < 0) return "EXPIRED " + (-d) + "d ago";
    return d + " days left";
  }

  function daysClass(d) {
    if (d == null) return "";
    if (d <= 30) return "txt-red";
    if (d <= 90) return "txt-amber";
    return "txt-green";
  }

  async function api(method, url, body) {
    const opts = { method, headers: {} };
    if (body instanceof FormData) {
      opts.body = body;
    } else if (body) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (res.status === 401) { location.href = portalRestartPending ? "/login?updated=1" : "/login"; return null; }
    try { return await res.json(); } catch (e) { return { error: "HTTP " + res.status }; }
  }

  // ── Terminal ─────────────────────────────────────────
  const term = {
    el: null,
    outputEl: null,

    init() {
      this.el = $("#terminal");
      $("#btn-clear").addEventListener("click", () => this.clear());
      $("#btn-copy").addEventListener("click", () => this.copy());
    },

    copy() {
      const text = this.el.innerText;
      const btn = $("#btn-copy");
      const done = (ok) => { btn.textContent = ok ? "Copied" : "Select + Ctrl-C"; setTimeout(() => { btn.textContent = "Copy"; }, 2500); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => done(true), () => done(false));
      } else {
        const range = document.createRange();
        range.selectNodeContents(this.el);
        const sel = window.getSelection();
        sel.removeAllRanges(); sel.addRange(range);
        done(document.execCommand && document.execCommand("copy"));
      }
    },

    clear() {
      this.el.innerHTML = "";
      this.writeLine("Terminal cleared.", "term-info");
    },

    writeLine(text, cls) {
      const div = document.createElement("div");
      div.className = "term-line " + (cls || "");
      div.textContent = text;
      this.el.appendChild(div);
      this.scrollBottom();
    },

    writeHTML(html, cls) {
      const div = document.createElement("div");
      div.className = "term-line " + (cls || "");
      div.innerHTML = html;
      this.el.appendChild(div);
      this.scrollBottom();
    },

    writeDivider() {
      const hr = document.createElement("hr");
      hr.className = "term-divider";
      this.el.appendChild(hr);
    },

    writePrompt(cmd) {
      this.writeHTML(
        '<span class="term-prompt">root@tak-server</span>:<span style="color:#5eadf2">~</span>$ ' +
        '<span class="term-cmd">' + esc(cmd) + '</span>'
      );
    },

    getOrCreateOutput() {
      if (!this.outputEl || !this.el.contains(this.outputEl)) {
        this.outputEl = document.createElement("div");
        this.outputEl.className = "term-line term-output";
        this.el.appendChild(this.outputEl);
      }
      return this.outputEl;
    },

    appendOutput(text) {
      const el = this.getOrCreateOutput();
      el.textContent += text;
      this.scrollBottom();
    },

    finishOutput() { this.outputEl = null; },

    showCursor() {
      this.removeCursor();
      const span = document.createElement("span");
      span.className = "term-cursor";
      span.id = "term-cursor-el";
      this.el.appendChild(span);
      this.scrollBottom();
    },

    removeCursor() {
      const c = document.getElementById("term-cursor-el");
      if (c) c.remove();
    },

    scrollBottom() { this.el.scrollTop = this.el.scrollHeight; },

    focus() {
      $("#terminal-section").scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };

  // ── TAK Server Status ──────────────────────────────
  async function refreshStatus() {
    try {
      const data = await api("GET", "/api/status");
      if (!data) return;
      const badge = $("#tak-status");
      const s = data.takserver_status;
      badge.textContent = "TAK: " + s + (s === "active" && data.listening_8089 === false ? " (8089 not listening)" : "");
      badge.className = "status-badge " + (s === "active" ? "status-active" : s === "inactive" || s === "failed" ? "status-inactive" : "status-unknown");
      const v = data.version || {};
      const vs = $("#tak-version");
      if (vs) {
        const mismatch = !!(v.version && v.war && !v.war.startsWith(v.version));
        vs.textContent = v.version ? (mismatch ? v.version + " (war: " + v.war + ")" : v.version) : "version unknown";
        vs.classList.toggle("mismatch", mismatch);
        vs.title = v.package ? "Installed package " + v.package + " (" + v.source + ")" + (v.war ? "; takserver.war says " + v.war : "")
                 : v.war ? "From takserver.war; dpkg / rpm know no takserver package" : "No takserver package found and no takserver.war to read";
      }
      const iv = $("#installed-version");
      if (iv) iv.textContent = v.version || "unknown";
    } catch (e) { /* ignore */ }
  }

  // ── File List ──────────────────────────────────────
  async function refreshFiles() {
    const data = await api("GET", "/api/uploads");
    if (!data || !Array.isArray(data)) return;
    const container = $("#file-list");

    if (data.length === 0) {
      container.innerHTML = '<p class="muted">No packages uploaded yet.</p>';
      return;
    }

    container.innerHTML = data.map(f => `
      <div class="file-item${selectedFile === f.name ? ' selected' : ''}" data-name="${esc(f.name)}">
        <div class="file-item-info">
          <div class="file-item-name">${esc(f.name)}</div>
          <div class="file-item-meta">${formatSize(f.size)} &middot; ${timeAgo(f.mtime)}</div>
        </div>
        <div class="file-item-actions">
          <button class="btn-delete" data-name="${esc(f.name)}" title="Delete package">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
          </button>
        </div>
      </div>
    `).join("");

    container.querySelectorAll(".file-item-info").forEach(el => {
      el.addEventListener("click", () => selectFile(el.closest(".file-item").dataset.name));
    });
    container.querySelectorAll(".btn-delete").forEach(el => {
      el.addEventListener("click", (e) => { e.stopPropagation(); deleteFile(el.dataset.name); });
    });
  }

  function selectFile(name) {
    selectedFile = name;
    $$(".file-item").forEach(el => el.classList.toggle("selected", el.dataset.name === name));
    $("#btn-install").disabled = false;
    $("#install-cmd").textContent = platform.install_tpl.replace("{file}", name);
    $("#selected-file-msg").textContent = `Selected: ${name}`;
  }

  async function deleteFile(name) {
    if (!confirm(`Delete "${name}"?\n\nThis cannot be undone.`)) return;
    const data = await api("POST", "/api/delete", { filename: name });
    if (data && data.ok) {
      if (selectedFile === name) {
        selectedFile = null;
        $("#btn-install").disabled = true;
        $("#install-cmd").innerHTML = `<em>${esc(platform.install_tpl.replace("{file}", "file" + platform.pkg_ext))}</em>`;
        $("#selected-file-msg").textContent = "Select an uploaded package above to enable install.";
      }
      refreshFiles();
    }
  }

  // ── File Upload (TAK packages and TerraTAK image tarballs share one uploader) ──
  function setupUploader(cfg) {
    const zone = $(cfg.zone), input = $(cfg.input), progress = $(cfg.progress), fill = $(cfg.fill), text = $(cfg.text);
    const content = zone.querySelector(".drop-zone-content");

    zone.addEventListener("click", (e) => { if (e.target.tagName !== "LABEL") input.click(); });
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("drag-over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      zone.classList.remove("drag-over");
      if (e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);
    });
    input.addEventListener("change", () => { if (input.files.length) upload(input.files[0]); input.value = ""; });

    function upload(file) {
      const exts = cfg.accept();
      if (!exts.some(x => file.name.endsWith(x))) { alert(`Only ${exts.join(" / ")} files are allowed here.`); return; }
      const xhr = new XMLHttpRequest();
      progress.style.display = "block";
      content.style.display = "none";
      fill.style.width = "0%";
      fill.style.background = "";
      text.textContent = "Uploading…";

      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          fill.style.width = pct + "%";
          text.textContent = `Uploading… ${pct}% (${formatSize(e.loaded)} / ${formatSize(e.total)})`;
        }
      });

      const done = (ok, msg) => {
        text.textContent = msg;
        fill.style.width = "100%";
        fill.style.background = ok ? "var(--green)" : "var(--red)";
        term.writeDivider();
        term.writeLine(msg, ok ? "term-success" : "term-error");
        setTimeout(() => {
          progress.style.display = "none";
          content.style.display = "";
          fill.style.width = "0%";
          fill.style.background = "";
        }, ok ? 2500 : 6000);
      };
      xhr.addEventListener("load", () => {
        let res = null;
        try { res = JSON.parse(xhr.responseText); } catch (e) { /* not json */ }
        if (xhr.status === 200 && res && res.ok) { done(true, `Uploaded ${res.filename} (${formatSize(res.size)})`); cfg.onDone(res); }
        else done(false, "Upload failed: " + (res && res.error ? res.error : "HTTP " + xhr.status));
      });
      xhr.addEventListener("error", () => done(false, "Upload failed: the connection dropped"));

      // the raw file is the body: the server streams it to disk instead of holding it in memory
      xhr.open("POST", "/api/upload?kind=" + cfg.kind + "&name=" + encodeURIComponent(file.name));
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.send(file);
    }
  }

  function setupUpload() {
    setupUploader({
      zone: "#drop-zone", input: "#file-input", progress: "#upload-progress", fill: "#progress-fill", text: "#progress-text",
      kind: "package", accept: () => [".deb", ".rpm"],
      onDone: (res) => { selectedFile = res.filename; refreshFiles().then(() => selectFile(res.filename)); },
    });
    setupUploader({
      zone: "#tt-drop-zone", input: "#tt-file-input", progress: "#tt-upload-progress", fill: "#tt-progress-fill", text: "#tt-progress-text",
      kind: "terratak", accept: () => [".tar"],
      onDone: () => loadTerraTAK(),
    });
  }

  // ── Jobs (shell commands and certificate jobs share the terminal) ──
  function setBusy(busy) {
    $$(".btn-action, .job-btn").forEach(b => b.disabled = busy);
    if (!busy && !selectedFile) $("#btn-install").disabled = true;
    $("#job-pill").style.display = busy ? "" : "none";
  }

  function beginJob(data, isCertJob) {
    activeCmdId = data.cmd_id;
    activeIsCertJob = !!isCertJob;
    cmdFinished = false;
    const badge = $("#term-status");
    badge.style.display = "";
    badge.textContent = "running";
    badge.className = "status-badge status-running";
    term.writeDivider();
    term.writePrompt(data.command);
    term.finishOutput();
    term.showCursor();
    $("#btn-stop").style.display = isCertJob ? "none" : "";
    lastOutputLen = 0;
    setBusy(true);
    if (isCertJob) term.focus();
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = setInterval(() => pollLog(data.cmd_id), 500);
    pollLog(data.cmd_id);
  }

  function setupActions() {
    $("#btn-install").addEventListener("click", () => { if (selectedFile) runAction("install", selectedFile); });
    $("#btn-daemon-reload").addEventListener("click", () => runAction("daemon-reload"));
    $("#btn-restart").addEventListener("click", () => runAction("restart"));
    $("#btn-tail-log").addEventListener("click", () => runAction("tail-log", null, true));
    $("#btn-stop").addEventListener("click", () => stopCommand());
  }

  async function runAction(action, filename, skipConfirm) {
    const labels = {
      "install": `Install ${filename || "package"}`,
      "daemon-reload": "Daemon Reload",
      "restart": "Restart TAK Server",
      "tail-log": "Tail Server Log",
    };
    if (!skipConfirm && !confirm(`Run "${labels[action]}"?\n\nThis will execute a system command.`)) return;
    const data = await api("POST", "/api/run", { action, filename });
    if (!data || !data.ok) {
      alert("Failed to start command: " + (data && data.error ? data.error : "unknown error"));
      return;
    }
    beginJob(data, false);
  }

  async function stopCommand() {
    if (!activeCmdId) return;
    await api("POST", "/api/stop", { cmd_id: activeCmdId });
  }

  async function pollLog(cmdId) {
    if (cmdFinished) return;
    let data;
    try { data = await api("GET", "/api/logs/" + cmdId); }
    catch (e) {                     // the portal went away mid-job: only its own restart does that
      if (activeIsPortalUpdate && portalRestartPending) { endPolling(); activeIsPortalUpdate = false; waitForPortalRestart(); }
      return;
    }
    if (!data || data.error) return;

    const newText = data.output.substring(lastOutputLen);
    if (newText.length > 0) {
      term.removeCursor();
      term.appendOutput(newText);
      if (data.status === "running") term.showCursor();
      lastOutputLen = data.output.length;
    }

    if (data.status === "success" || data.status === "error" || data.status === "stopped") {
      if (cmdFinished) return;
      cmdFinished = true;
      clearInterval(pollingTimer);
      pollingTimer = null;
      activeCmdId = null;
      term.removeCursor();
      term.finishOutput();
      $("#btn-stop").style.display = "none";

      if (data.status === "stopped") {
        term.writeLine("Stopped by user.", "term-info");
      } else if (data.exit_code !== null && data.exit_code !== 0) {
        term.writeLine(activeIsCertJob ? "Job did not complete. Read the lines above." : `Process exited with code ${data.exit_code}`, "term-error");
      } else {
        term.writeLine("Command completed successfully.", "term-success");
      }

      const badge = $("#term-status");
      badge.textContent = data.status;
      badge.className = "status-badge status-" + data.status;
      setTimeout(() => { badge.style.display = "none"; }, 3000);

      setBusy(false);
      if (activeIsPortalUpdate) {
        activeIsPortalUpdate = false;
        if (portalRestartPending && data.exit_code === 0 && data.output.indexOf("UPDATE COMPLETE") !== -1) { waitForPortalRestart(); return; }
        portalRestartPending = false;
        loadPortalInfo();
        return;
      }
      setTimeout(refreshStatus, 2000);
      if (activeIsCertJob) { loadCerts(); if (liveRows) loadLive(); loadSnapshots(); }
      loadTerraTAK();
    }
  }

  function endPolling() {
    cmdFinished = true;
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = null;
    activeCmdId = null;
    term.removeCursor();
    term.finishOutput();
    $("#btn-stop").style.display = "none";
    setBusy(false);
  }

  /** After a successful update the unit restarts; sessions live in memory, so the first 401 means it is back. */
  async function waitForPortalRestart() {
    term.writeLine("Waiting for the portal to come back...", "term-info");
    const started = Date.now();
    let down = false;
    while (Date.now() - started < 120000) {
      await new Promise(r => setTimeout(r, 1000));
      try {
        const res = await fetch("/api/status", { cache: "no-store" });
        if (res.status === 401 || (down && res.ok)) { location.href = "/login?updated=1"; return; }
      } catch (e) { down = true; }
    }
    term.writeLine("The portal did not come back within two minutes. On the server: journalctl -u tak-portal -e", "term-error");
  }

  /** Confirm, ask for the portal password when the action is destructive, POST, stream. */
  async function startCertJob(op, body, confirmText, needPassword) {
    if (confirmText && !confirm(confirmText)) return;
    if (needPassword) {
      const pw = prompt("Enter the portal password to continue:");
      if (!pw) return;
      body.password = pw;
    }
    const data = await api("POST", "/api/certs/" + op, body);
    if (!data || !data.ok) {
      alert(data && data.error ? data.error : "Could not start the job");
      return;
    }
    beginJob(data, true);
  }

  // ── Platform Detection ─────────────────────────────
  async function fetchPlatform() {
    try {
      const data = await api("GET", "/api/platform");
      if (data && data.pkg_ext) {
        platform = data;
        platform.install_tpl = data.install_tpl || `sudo ${data.pkg_mgr} install -y ./{file}`;
        const ext = platform.pkg_ext;
        const extLabel = $("#pkg-ext-label");
        if (extLabel) extLabel.textContent = ext;
        $$(".pkg-ext-text").forEach(el => { el.textContent = ext; });
        const installCmd = $("#install-cmd");
        if (installCmd) installCmd.innerHTML = `<em>${esc(platform.install_tpl.replace("{file}", "file" + ext))}</em>`;
        const fileInput = $("#file-input");
        if (fileInput) fileInput.accept = ext;
      }
    } catch (e) { /* use defaults */ }
  }

  // ── Settings (FQDN) ────────────────────────────────
  async function loadSettings() {
    const d = await api("GET", "/api/settings");
    if (!d) return;
    $("#fqdn-input").value = d.fqdn || "";
    $("#fqdn-input").placeholder = d.default_host || "tak.example.com";
  }

  async function saveSettings() {
    const msg = $("#fqdn-msg");
    const d = await api("POST", "/api/settings", { fqdn: $("#fqdn-input").value.trim() });
    if (d && d.ok) { msg.textContent = "Saved."; msg.className = "txt-green"; loadCerts(); }
    else { msg.textContent = d && d.error ? d.error : "Failed"; msg.className = "txt-red"; }
    setTimeout(() => { msg.textContent = ""; }, 4000);
  }

  // ── Certificates: status ───────────────────────────
  function tile(nameId, expId, info) {
    if (!info) { $(nameId).textContent = "not found"; $(expId).textContent = ""; return; }
    $(nameId).textContent = info.name || "?";
    $(expId).innerHTML = info.expires ? `expires ${esc(info.expires)} &middot; <span class="${daysClass(info.days_left)}">${esc(daysText(info.days_left))}</span>` : "";
  }

  async function loadCerts() {
    const d = await api("GET", "/api/certs/status");
    if (!d) return;
    certs = d;
    const problems = $("#certs-problems");
    if (d.error) {
      problems.style.display = "";
      problems.textContent = d.error;
      return;
    }
    if (!d.installed) {
      problems.style.display = "";
      problems.textContent = "TAK Server certificate scripts were not found under /opt/tak/certs. Certificate management needs a native TAK Server install on this box.";
      $$(".job-btn").forEach(b => b.disabled = true);
    } else if (d.problems && d.problems.length) {
      problems.style.display = "";
      problems.textContent = d.problems.join(" ");
      $$(".job-btn").forEach(b => b.disabled = true);
    } else {
      problems.style.display = "none";
    }

    tile("#ca-root-name", "#ca-root-exp", d.root);
    tile("#ca-int-name", "#ca-int-exp", d.intermediate);
    renderPassword();

    // connectors: a 8446 keystore that does not exist (installTAK's Let's Encrypt step after a failed certbot run)
    const connRow = $("#ca-connector-row");
    const dangling = d.dangling_connectors || [];
    const le = (d.connectors || []).find(c => c.keystoreFile && c.exists);
    if (dangling.length) {
      connRow.style.display = "";
      connRow.innerHTML = `<div class="row-note-text"><strong class="txt-red">Port ${esc(dangling[0].port)} points at a keystore that does not exist:</strong> <code>${esc(dangling[0].keystoreFile)}</code>. This is what installTAK leaves behind when its Let's Encrypt step fails. TAK's API cannot bring that port up, and the renew cron restarts TAK Server twice a day. Resetting puts the port back on TAK's own certificate and removes the cron entries.</div>
        <div class="row-note-actions"><button class="btn btn-sm btn-primary job-btn" id="btn-reset-8446">Reset 8446 to TAK's certificate</button></div>`;
      $("#btn-reset-8446").addEventListener("click", () =>
        startCertJob("reset-8446", {}, "Put port 8446 back on TAK Server's own certificate?\n\n• CoreConfig.xml and CoreConfig.example.xml are backed up first\n• The Let's Encrypt renew cron entries are removed\n• TAK Server restarts; devices reconnect in about a minute", true));
    } else if (le) {
      connRow.style.display = "";
      connRow.innerHTML = `<div class="row-note-text">Port ${esc(le.port)} serves its own keystore <code>${esc(le.keystoreFile.split("/").pop())}</code> (Let's Encrypt). The portal leaves it alone, including across a root rotation.</div>`;
    } else {
      connRow.style.display = "none";
    }

    // server certificate
    const s = d.server || {};
    const signerEl = $("#ca-srv-signer");
    const signerRow = $("#ca-signer-row");
    const namesRow = $("#ca-names-row");
    if (!s.issuer_cn) {
      signerEl.textContent = "not found";
      $("#ca-srv-exp").textContent = "";
      signerRow.style.display = "none";
      namesRow.style.display = "none";
    } else {
      const modeLabel = s.mode === "root" ? "Root CA" : s.mode === "intermediate" ? "Intermediate CA" : "another CA";
      signerEl.innerHTML = `<span class="${s.mode === 'root' ? 'txt-green' : 'txt-amber'}">${modeLabel}</span> <span class="muted">(${esc(s.issuer_cn)})</span>`;
      $("#ca-srv-exp").innerHTML = (s.expires ? `expires ${esc(s.expires)} &middot; <span class="${daysClass(s.days_left)}">${esc(daysText(s.days_left))}</span>` : "")
        + (s.live ? (s.live_issuer_cn && s.live_issuer_cn !== s.issuer_cn ? ` &middot; <span class="txt-amber">live cert is signed by ${esc(s.live_issuer_cn)}: restart TAK</span>` : "") : ' &middot; <span class="txt-amber">TAK not answering on 8443</span>');

      signerRow.style.display = "";
      let text, btns = "";
      if (s.mode === "root") {
        text = "Rotating the intermediate CA will <strong>not</strong> disconnect devices: they keep connecting while users move to the new CA.";
        btns = `<button class="btn btn-sm btn-outline job-btn" data-signer="intermediate">Switch to intermediate-signed</button>`;
      } else if (s.mode === "intermediate") {
        text = "Rotating the intermediate CA <strong class=\"txt-amber\">will disconnect every device</strong> until it re-enrolls, because the server certificate chains through the intermediate. Signing it with the root CA avoids that.";
        btns = `<button class="btn btn-sm btn-primary job-btn" data-signer="root">Switch to root-signed</button>`;
      } else {
        text = "The server certificate is not signed by this server's current root or intermediate CA. Reissue it with one of them.";
        btns = `<button class="btn btn-sm btn-primary job-btn" data-signer="root">Sign with the root CA</button> <button class="btn btn-sm btn-outline job-btn" data-signer="intermediate">Sign with the intermediate CA</button>`;
      }
      if (!s.root_key_present) btns = `<span class="txt-amber">The root CA's private key is not on this server.</span>`;
      signerRow.innerHTML = `<div class="row-note-text">${text}</div><div class="row-note-actions">${btns}</div>`;
      signerRow.querySelectorAll("[data-signer]").forEach(b => b.addEventListener("click", () => switchSigner(b.dataset.signer)));

      // names
      const missing = s.missing_names || [];
      if (s.live && missing.length) {
        namesRow.style.display = "";
        namesRow.innerHTML = `<div class="row-note-text">The live server certificate is missing <strong>${esc(missing.join(", "))}</strong>. ATAK does not check names, but anything that verifies the hostname rejects the server. Reissuing keeps the CA, so nobody re-enrolls.<br><span class="muted">On the certificate now: ${esc((s.live_names || []).join(", ") || "none")}</span></div>
          <div class="row-note-actions"><button class="btn btn-sm btn-outline job-btn" id="btn-reissue-server">Reissue with this server's names</button></div>`;
        $("#btn-reissue-server").addEventListener("click", () =>
          startCertJob("reissue-server", {}, "Reissue TAK Server's certificate with this server's names?\n\n• The CA stays the same, so enrolled devices keep working\n• TAK Server restarts; devices reconnect in about a minute\n• The current certificate is backed up first and restored if anything fails", true));
      } else {
        namesRow.style.display = "none";
      }
    }

    // rotate card text + suggestions
    const rotDesc = $("#rotate-desc");
    const base = "Creates a new intermediate CA signed by your root CA, reissues the server and client certificates on it, and keeps the old intermediate trusted until you revoke it. ";
    if (s.mode === "root") rotDesc.innerHTML = base + '<strong class="txt-green">Devices keep connecting.</strong> Hand out the new truststore and have users re-enroll at their own pace.';
    else rotDesc.innerHTML = base + '<strong class="txt-red">Every device disconnects</strong> until it imports the new truststore or re-enrolls. Switch the server certificate to root-signed first to avoid this.';
    if (!$("#rot-name").value && d.suggested_name) $("#rot-name").value = d.suggested_name;
    if (!$("#root-name").value && d.suggested_root) $("#root-name").value = d.suggested_root;
    if (!$("#root-int-name").value && d.intermediate) $("#root-int-name").value = suggestInt(d.intermediate.name);
    if (d.root && d.root.days_left) {
      $("#rot-days").max = Math.min(3652, d.root.days_left);
      if (parseInt($("#rot-days").value, 10) > d.root.days_left) $("#rot-days").value = d.root.days_left;
    }

    // rotation window
    const rw = $("#rotation-window");
    const rot = d.rotation || {};
    if (rot.old && rot.new) {
      rw.style.display = "";
      const when = new Date((rot.at || 0) * 1000).toLocaleDateString();
      rw.innerHTML = `<strong>Rotation in progress:</strong> ${esc(rot.old)} &rarr; ${esc(rot.new)} on ${esc(when)}. ${rot.signer === "root" ? "Devices stayed connected." : "Devices were disconnected."} Use <em>Live certificates by CA</em> to see who is still on ${esc(rot.old)}, then revoke it from the trust list.`;
    } else {
      rw.style.display = "none";
    }

    renderTrustList(d);
    renderClients(d);
  }

  function suggestInt(name) {
    const m = /^(.*?)(\d+)$/.exec(name || "");
    if (m) return m[1] + "01";
    return "INTERMEDIATE-CA-01";
  }

  function renderPassword() {
    const el = $("#ca-pass");
    const pw = certs && certs.password ? certs.password : "";
    el.textContent = passShown ? pw : "••••••";
    $("#ca-pass-toggle").textContent = passShown ? "hide" : "show";
  }

  function renderTrustList(d) {
    const wrap = $("#ts-table-wrap");
    const ts = d.truststore;
    $("#ts-file").textContent = ts ? "(" + ts.file + ")" : "";
    const dl = $("#dl-truststore");
    if (ts && ts.p12) { dl.href = "/api/certs/download/" + encodeURIComponent(ts.p12); dl.style.display = ""; }
    else dl.style.display = "none";
    if (!ts) {
      wrap.innerHTML = '<p class="muted txt-amber">Could not tell which truststore TAK Server is using (CoreConfig.xml and ca.pem name none here). Nothing to revoke from.</p>';
      return;
    }
    if (!ts.readable) {
      wrap.innerHTML = `<p class="muted txt-amber">${esc(ts.file)} could not be read with the current certificate password.</p>`;
      return;
    }
    const roleLabel = { root: '<span class="role role-root">root</span>', current: '<span class="role role-current">current</span>', old: '<span class="role role-old">old</span>', key: '<span class="role">key</span>' };
    let h = '<table class="tbl"><thead><tr><th>Alias</th><th>Certificate (CN)</th><th>Role</th><th>Expires</th><th></th></tr></thead><tbody>';
    (ts.entries || []).forEach(e => {
      const rev = e.role === "old" ? `<button class="btn btn-sm btn-danger-outline job-btn" data-revoke="${esc(e.alias)}" data-cn="${esc(e.cn)}">Revoke</button>` : "";
      h += `<tr><td><code>${esc(e.alias)}</code></td><td>${esc(e.cn)}</td><td>${roleLabel[e.role] || esc(e.role)}</td><td>${esc(e.expires)} <span class="${daysClass(e.days_left)}">${esc(daysText(e.days_left))}</span></td><td class="ta-right">${rev}</td></tr>`;
    });
    h += "</tbody></table>";
    if (ts.has_root) h += '<p class="muted small txt-amber">A root CA is in TAK Server\'s trust list. Java treats every entry as a trust anchor, so a device could present an old root-signed intermediate in its own chain and still be accepted. Revoke removes roots from this list; the truststore handed to devices keeps the root.</p>';
    if (ts.signing) h += `<p class="muted small">Enrollment (8446) signs with <code>${esc(ts.signing.split("/").pop())}</code>${ts.validity_days ? ", issued certificates valid " + esc(ts.validity_days) + " days" : ""}.</p>`;
    wrap.innerHTML = h;
    wrap.querySelectorAll("[data-revoke]").forEach(b => b.addEventListener("click", () => revokeCA(b.dataset.revoke, b.dataset.cn)));
  }

  function renderClients(d) {
    const wrap = $("#client-list");
    const list = d.clients || [];
    if (!list.length) { wrap.innerHTML = '<p class="muted">No client certificates found.</p>'; return; }
    let h = '<table class="tbl"><thead><tr><th>Name</th><th>Signed by</th><th>Expires</th><th></th></tr></thead><tbody>';
    list.forEach(c => {
      const flag = c.on_current ? '<span class="txt-green">✓</span>' : c.root_signed ? '<span class="txt-amber" title="signed directly by the root CA: blocks Revoke until reissued">root-signed</span>' : '<span class="txt-amber" title="not on the current intermediate">old CA</span>';
      h += `<tr><td><strong>${esc(c.name)}</strong></td><td>${esc(c.issuer_cn)} ${flag}</td><td>${esc(c.expires)} <span class="${daysClass(c.days_left)}">${esc(daysText(c.days_left))}</span></td>
        <td class="ta-right"><a class="btn btn-sm btn-outline" href="/api/certs/download/${encodeURIComponent(c.name)}.p12">&#8595; .p12</a> <a class="btn btn-sm btn-outline" href="/api/certs/package?client=${encodeURIComponent(c.name)}" title="truststore + this .p12 + config.pref">&#8595; package</a></td></tr>`;
    });
    h += "</tbody></table>";
    wrap.innerHTML = h;
  }

  // ── Certificates: live table ───────────────────────
  async function loadLive() {
    const btn = $("#btn-live");
    btn.disabled = true; btn.textContent = "Loading…";
    const d = await api("GET", "/api/certs/live");
    btn.disabled = false; btn.textContent = "Refresh";
    const sum = $("#live-summary");
    const wrap = $("#live-table-wrap");
    if (!d || !d.ok) {
      sum.style.display = "";
      sum.innerHTML = `<span class="txt-red">${esc(d && d.error ? d.error : "Could not read the certificate table")}</span>`;
      wrap.innerHTML = "";
      liveRows = null;
      return;
    }
    liveRows = d;
    $("#live-search").style.display = "";
    const counts = d.counts || {};
    const cur = (d.current_ca || "").toLowerCase();
    const parts = Object.keys(counts).sort((a, b) => (a === cur ? -1 : b === cur ? 1 : a.localeCompare(b)))
      .map(k => `<span class="pill ${k === cur ? 'pill-green' : 'pill-amber'}">${esc(k || "(unknown CA)")}: ${counts[k]}</span>`);
    const stale = Object.keys(counts).filter(k => k !== cur).reduce((n, k) => n + counts[k], 0);
    sum.style.display = "";
    sum.innerHTML = `<div class="row-note-text">${d.rows.length} live certificate(s) across ${d.total} client UID(s). ${stale ? `<strong class="txt-amber">${stale} still on an old CA.</strong>` : '<strong class="txt-green">Everyone is on ' + esc(d.current_ca) + '.</strong>'}</div><div class="pills">${parts.join(" ")}</div>`;
    renderLive();
  }

  function renderLive() {
    const d = liveRows;
    if (!d) return;
    const q = ($("#live-search").value || "").trim().toLowerCase();
    const cur = (d.current_ca || "").toLowerCase();
    const rows = d.rows.filter(r => !q || [r.user, r.uid, r.issuer_cn, r.subject_cn].some(v => (v || "").toLowerCase().includes(q)));
    let h = '<table class="tbl"><thead><tr><th>User</th><th>Client UID</th><th>Signed by</th><th>Expires</th></tr></thead><tbody>';
    rows.slice(0, 500).forEach(r => {
      const onCur = (r.issuer_cn || "").toLowerCase() === cur;
      const exp = r.expires ? new Date(r.expires * 1000).toISOString().slice(0, 10) : "";
      h += `<tr><td>${esc(r.user || r.subject_cn || "")}</td><td><code>${esc(r.uid)}</code></td><td class="${onCur ? 'txt-green' : 'txt-amber'}">${esc(r.issuer_cn || "?")}</td><td>${esc(exp)}</td></tr>`;
    });
    h += "</tbody></table>";
    if (rows.length > 500) h += `<p class="muted small">Showing 500 of ${rows.length}; narrow the filter.</p>`;
    if (!rows.length) h = '<p class="muted">Nothing matches.</p>';
    $("#live-table-wrap").innerHTML = h;
  }

  // ── Snapshots ──────────────────────────────────────
  async function loadSnapshots() {
    const wrap = $("#snap-table-wrap");
    const d = await api("GET", "/api/snapshots");
    if (!d) return;
    if (!d.ok) { wrap.innerHTML = `<p class="muted txt-red">${esc(d.error || "Could not list snapshots")}</p>`; return; }
    if (d.dir) $("#snap-dir").textContent = d.dir;
    const items = d.items || [];
    if (!items.length) { wrap.innerHTML = '<p class="muted">No snapshots yet. One is saved automatically before every certificate job.</p>'; return; }
    let h = '<table class="tbl"><thead><tr><th>Name</th><th>Taken</th><th>Size</th><th>Intermediate then</th><th></th></tr></thead><tbody>';
    items.forEach(s => {
      const when = new Date(s.created * 1000).toLocaleString();
      h += `<tr><td><code>${esc(s.name)}</code>${s.auto ? ' <span class="muted small">auto</span>' : ""}</td><td>${esc(when)} <span class="muted small">(${esc(timeAgo(s.created))})</span></td><td>${esc(formatSize(s.size))}</td><td>${esc(s.intermediate || "?")}</td>
        <td class="ta-right"><button class="btn btn-sm btn-outline" data-diff="${esc(s.name)}" title="What differs between this snapshot and the server now">Diff</button> <button class="btn btn-sm btn-danger-outline job-btn" data-restore="${esc(s.name)}">Restore</button> <button class="btn btn-sm btn-outline job-btn" data-snapdel="${esc(s.name)}" title="Delete this snapshot">&#10005;</button></td></tr>`;
    });
    h += "</tbody></table>";
    wrap.innerHTML = h;
    wrap.querySelectorAll("[data-diff]").forEach(b => b.addEventListener("click", () => diffSnapshot(b.dataset.diff)));
    wrap.querySelectorAll("[data-restore]").forEach(b => b.addEventListener("click", () => restoreSnapshot(b.dataset.restore)));
    wrap.querySelectorAll("[data-snapdel]").forEach(b => b.addEventListener("click", () => deleteSnapshot(b.dataset.snapdel)));
  }

  async function saveSnapshot() {
    const btn = $("#btn-snap-save");
    const name = $("#snap-name").value.trim();
    if (name && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(name)) { alert("Snapshot names: letters, numbers, dots, hyphens and underscores."); return; }
    btn.disabled = true;
    const d = await api("POST", "/api/snapshots/save", { name });
    btn.disabled = false;
    if (!d || !d.ok) { alert(d && d.error ? d.error : "Could not save the snapshot"); return; }
    $("#snap-name").value = "";
    term.writeDivider();
    term.writeLine(`Snapshot saved: ${d.item.name} (${formatSize(d.item.size)})`, "term-success");
    loadSnapshots();
  }

  async function diffSnapshot(name) {
    const d = await api("GET", "/api/snapshots/diff?name=" + encodeURIComponent(name));
    term.writeDivider();
    term.writePrompt(`portal: diff snapshot ${name}`);
    term.finishOutput();
    if (!d || !d.ok) { term.writeLine(d && d.error ? d.error : "Could not diff", "term-error"); return; }
    term.appendOutput(d.text + "\n");
    term.finishOutput();
    term.focus();
  }

  function restoreSnapshot(name) {
    startSnapshotJob("restore", name,
      `RESTORE snapshot "${name}"?\n\n• TAK Server stops, /opt/tak/certs and both CoreConfig files are replaced with the snapshot, TAK Server starts again\n• The state being replaced is kept as before-restore-<time>\n• Devices enrolled since the snapshot was taken may need to re-enroll; admin grants are kept (they live in the database)\n\nContinue?`);
  }

  async function deleteSnapshot(name) {
    if (!confirm(`Delete snapshot "${name}"?\n\nThis cannot be undone.`)) return;
    const pw = prompt("Enter the portal password to continue:");
    if (!pw) return;
    const d = await api("POST", "/api/snapshots/delete", { name, password: pw });
    if (!d || !d.ok) { alert(d && d.error ? d.error : "Could not delete the snapshot"); return; }
    loadSnapshots();
  }

  async function startSnapshotJob(op, name, confirmText) {
    if (!confirm(confirmText)) return;
    const pw = prompt("Enter the portal password to continue:");
    if (!pw) return;
    const d = await api("POST", "/api/snapshots/" + op, { name, password: pw });
    if (!d || !d.ok) { alert(d && d.error ? d.error : "Could not start the job"); return; }
    beginJob(d, true);
  }

  // ── Portal self-update ─────────────────────────────
  async function loadPortalInfo() {
    try {
      const d = await api("GET", "/api/portal");
      if (!d) return;
      portalInfo = d;
      const v = $("#pu-version"), note = $("#pu-note");
      if (!d.ok) { v.textContent = d.error || "unknown"; return; }
      if (!d.git) v.innerHTML = '<span class="txt-amber">git is not installed on this server (apt-get install -y git / dnf install -y git)</span>';
      else if (!d.clone) v.innerHTML = `copied files in <code>${esc(d.dir)}</code>, not a git checkout yet`;
      else v.innerHTML = `<code>${esc(d.commit || "?")}</code> ${esc(d.date)} <span class="muted">${esc(d.subject)}</span> on <code>${esc(d.branch)}</code>` + (d.remote ? ` from <code>${esc(d.remote)}</code>` : "");
      if (d.dirty && d.dirty.length) {
        note.style.display = "";
        note.textContent = "Files changed on this server: " + d.dirty.join(", ") + ". Update refuses to overwrite them (git stash on the server first).";
      } else note.style.display = "none";
      const url = (d.clone && d.remote) || d.repo || "";
      if (!$("#pu-repo").value && url && url.indexOf("***") === -1) $("#pu-repo").value = url;
      if (!$("#pu-branch").value) $("#pu-branch").value = (d.clone && d.branch) || d.wanted_branch || "main";
      $("#pu-token").placeholder = d.token_set ? "token saved (leave blank to keep it)" : "access token (private repository, optional)";
      $("#pu-token-clear").style.display = d.token_set ? "" : "none";
    } catch (e) { /* the portal may be restarting */ }
  }

  async function savePortalSettings(clearToken) {
    const pw = prompt("Enter the portal password to save the update settings:");
    if (!pw) return;
    const msg = $("#pu-msg");
    const d = await api("POST", "/api/portal/settings", {
      password: pw, repo: $("#pu-repo").value.trim(), branch: $("#pu-branch").value.trim(),
      token: clearToken ? "" : $("#pu-token").value, clear_token: !!clearToken,
    });
    if (d && d.ok) { msg.textContent = "Saved."; msg.className = "txt-green"; $("#pu-token").value = ""; loadPortalInfo(); }
    else { msg.textContent = d && d.error ? d.error : "Could not save"; msg.className = "txt-red"; }
  }

  async function checkPortalUpdate() {
    const d = await api("POST", "/api/portal/check", {});
    if (!d || !d.ok) { alert(d && d.error ? d.error : "Could not start the check"); return; }
    beginJob(d, true);
    activeIsPortalUpdate = true;
    portalRestartPending = false;
  }

  async function updatePortal() {
    const restart = $("#pu-restart").checked, skip = $("#pu-skip-tests").checked;
    const what = portalInfo && portalInfo.clone ? "Fast-forward this checkout to the repository" : "Fetch the repository into this folder (the copied files become a git checkout; uploads, logs and settings stay)";
    if (!confirm(`UPDATE THE PORTAL?\n\n• ${what}\n• The current files are backed up to backups/ first\n• ${skip ? "Self-tests SKIPPED" : "The self-tests run; if they fail the update rolls back"}\n• ${restart ? "The portal restarts afterwards and you sign in again" : "No restart; the new files run after the next restart"}\n\nTAK Server is not touched. Continue?`)) return;
    const pw = prompt("Enter the portal password to continue:");
    if (!pw) return;
    const d = await api("POST", "/api/portal/update", { password: pw, restart, skip_tests: skip });
    if (!d || !d.ok) { alert(d && d.error ? d.error : "Could not start the update"); return; }
    beginJob(d, true);
    activeIsPortalUpdate = true;
    portalRestartPending = restart;
  }

  function setupPortal() {
    $("#pu-save").addEventListener("click", () => savePortalSettings(false));
    $("#pu-token-clear").addEventListener("click", () => { if (confirm("Forget the saved access token?")) savePortalSettings(true); });
    $("#pu-check").addEventListener("click", checkPortalUpdate);
    $("#pu-update").addEventListener("click", updatePortal);
  }

  // ── TerraTAK ───────────────────────────────────────
  async function loadTerraTAK() {
    try {
      const d = await api("GET", "/api/terratak");
      if (!d) return;
      tt = d;
      const set = (id, main, sub, cls) => {
        const m = $(id); m.textContent = main; m.className = cls || "";
        const s = $(id + "-sub"); if (s) s.textContent = sub || "";
      };
      if (!d.ok) { set("#tt-engine", "error", d.error, "txt-red"); return; }
      $("#tt-arch").textContent = d.arch;
      const problems = $("#tt-problems");
      if (d.problems && d.problems.length) { problems.style.display = ""; problems.textContent = d.problems.join(" "); }
      else problems.style.display = "none";
      $("#tt-install-engine").style.display = d.engine ? "none" : "";
      const eng = !!(d.engine && d.daemon);
      set("#tt-engine", d.engine ? d.engine + (d.daemon ? "" : " (not running)") : "none", d.engine_version, eng ? "txt-green" : "txt-amber");
      const imgs = d.images || [];
      set("#tt-image", imgs.length ? imgs.map(i => i.name.replace("terratak:", "")).join(", ") : "none", imgs.length ? imgs[0].size : (eng ? "upload a tarball below" : ""));
      const c = d.container;
      if (!c) set("#tt-container", "none", eng ? "install an image below" : "", "muted");
      else set("#tt-container", c.running ? "running" + (c.health ? " (" + c.health + ")" : "") : c.status,
               c.image + (c.ports ? " on " + c.ports : "") + (c.started ? ", since " + c.started : ""),
               c.running ? (c.health === "unhealthy" ? "txt-amber" : "txt-green") : "txt-red");
      const u = $("#tt-url"), us = $("#tt-url-sub");
      if (c && c.running && d.url) {
        u.innerHTML = `<a href="${esc(d.url)}" target="_blank" rel="noopener">${esc(d.url)}</a>`;
        us.textContent = d.settings.auth_set ? "login: " + d.settings.auth_user : "no login configured";
      } else { u.textContent = d.url || "–"; u.className = "muted"; us.textContent = c ? "container stopped" : ""; }
      const has = !!c, running = !!(c && c.running);
      $("#tt-start").disabled = !(eng && has && !running);
      $("#tt-stop").disabled = !(eng && running);
      $("#tt-restart").disabled = !(eng && running);
      $("#tt-logs").disabled = !(eng && has);
      $("#tt-remove").disabled = !(eng && has);
      $("#tt-remove-data").disabled = !eng;
      renderTTFiles(d);
      const s = d.settings || {};
      const fillIf = (id, v) => { const el = $(id); if (el && !el.dataset.touched) el.value = v == null ? "" : v; };
      fillIf("#tt-port", s.port); fillIf("#tt-mem", s.max_memory); fillIf("#tt-t3mem", s.t3_memory);
      fillIf("#tt-center", s.map_center); fillIf("#tt-user", s.auth_user);
      $("#tt-pass").placeholder = s.auth_set ? "password saved (leave blank to keep it)" : "password (6+ characters)";
      const fw = $("#tt-firewall"); if (!fw.dataset.touched) fw.checked = s.firewall !== false;
      $("#tt-auth-clear").style.display = s.auth_set ? "" : "none";
    } catch (e) { /* portal restarting */ }
  }

  function renderTTFiles(d) {
    const wrap = $("#tt-files");
    const files = d.files || [];
    if (!files.length) { wrap.innerHTML = '<p class="muted">No image tarballs uploaded yet.</p>'; return; }
    const eng = !!(d.engine && d.daemon);
    let h = '<table class="tbl"><thead><tr><th>File</th><th>Image</th><th>Built for</th><th>Size</th><th></th></tr></thead><tbody>';
    files.forEach(f => {
      const archOk = !f.arch || f.arch === d.arch;
      const loaded = (d.images || []).some(i => i.name === f.name);
      const current = d.container && d.container.image === f.name;
      h += `<tr><td><code>${esc(f.file)}</code> <span class="muted small">${esc(timeAgo(f.mtime))}</span></td>
        <td>${f.error ? `<span class="txt-red">${esc(f.error)}</span>` : esc(f.name) + (current ? ' <span class="txt-green small">running</span>' : loaded ? ' <span class="muted small">loaded</span>' : "")}</td>
        <td class="${archOk ? "" : "txt-red"}">${esc(f.arch || "?")}${archOk ? "" : " (this server is " + esc(d.arch) + ")"}</td>
        <td>${esc(formatSize(f.size))}</td>
        <td class="ta-right"><button class="btn btn-sm btn-primary job-btn" data-ttinstall="${esc(f.file)}" ${eng && !f.error && archOk ? "" : "disabled"}>${d.container ? (current ? "Reinstall" : "Upgrade to this") : "Install"}</button> <button class="btn btn-sm btn-outline" data-ttdel="${esc(f.file)}" title="Delete this file">&#10005;</button></td></tr>`;
    });
    h += "</tbody></table>";
    wrap.innerHTML = h;
    wrap.querySelectorAll("[data-ttinstall]").forEach(b => b.addEventListener("click", () => installTerraTAK(b.dataset.ttinstall)));
    wrap.querySelectorAll("[data-ttdel]").forEach(b => b.addEventListener("click", () => deleteTTFile(b.dataset.ttdel)));
  }

  async function ttJob(op, body, confirmText, needPassword) {
    if (confirmText && !confirm(confirmText)) return;
    body = body || {};
    if (needPassword) {
      const pw = prompt("Enter the portal password to continue:");
      if (!pw) return;
      body.password = pw;
    }
    const d = await api("POST", "/api/terratak/" + op, body);
    if (!d || !d.ok) { alert(d && d.error ? d.error : "Could not start"); return; }
    beginJob(d, true);
  }

  function installTerraTAK(file) {
    const s = (tt && tt.settings) || {};
    const upgrade = !!(tt && tt.container);
    ttJob("install", { file },
      `${upgrade ? "UPGRADE" : "INSTALL"} TerraTAK from ${file}?\n\n• Loads the image into ${tt ? tt.engine : "the container engine"}\n• ${upgrade ? "Replaces the current container; the data volume with your tilesets is kept" : "Creates the container 'terratak' with the data volume 'terratak-data'"}\n• Port ${s.port}${s.auth_set ? ", login required (" + s.auth_user + ")" : ", NO login: anyone who reaches the port can use and change it"}\n• ${s.firewall !== false ? "Opens the port in ufw / firewalld" : "Firewall left alone"}\n\nTAK Server is not touched. Continue?`, true);
  }

  async function deleteTTFile(name) {
    if (!confirm(`Delete ${name}?\n\nOnly the uploaded file goes; a loaded image or running container is not affected.`)) return;
    const d = await api("POST", "/api/terratak/delete-file", { name });
    if (!d || !d.ok) alert(d && d.error ? d.error : "Could not delete");
    loadTerraTAK();
  }

  async function ttLogs() {
    const d = await api("POST", "/api/terratak/logs", { lines: 200 });
    term.writeDivider();
    term.writePrompt("terratak: logs --tail 200");
    term.finishOutput();
    if (!d || !d.ok) { term.writeLine(d && d.error ? d.error : "no logs", "term-error"); return; }
    term.appendOutput((d.text || "(empty)") + "\n");
    term.finishOutput();
    term.focus();
  }

  async function saveTTSettings(clearAuth) {
    const pw = prompt("Enter the portal password to save the TerraTAK settings:");
    if (!pw) return;
    const body = { password: pw, port: $("#tt-port").value, max_memory: $("#tt-mem").value, t3_memory: $("#tt-t3mem").value,
                   map_center: $("#tt-center").value, auth_user: $("#tt-user").value, firewall: $("#tt-firewall").checked };
    if ($("#tt-pass").value) body.auth_pass = $("#tt-pass").value;
    if (clearAuth) body.clear_auth = true;
    const d = await api("POST", "/api/terratak/settings", body);
    const msg = $("#tt-msg");
    if (d && d.ok) {
      msg.textContent = "Saved. " + (d.note || ""); msg.className = "txt-green";
      $("#tt-pass").value = "";
      $$("#tt-card input").forEach(el => { delete el.dataset.touched; });
      loadTerraTAK();
    } else { msg.textContent = d && d.error ? d.error : "Could not save"; msg.className = "txt-red"; }
  }

  function setupTerraTAK() {
    $("#tt-start").addEventListener("click", () => ttJob("start"));
    $("#tt-stop").addEventListener("click", () => ttJob("stop", null, "Stop TerraTAK?\n\nDevices streaming its tiles lose the layer until it is started again."));
    $("#tt-restart").addEventListener("click", () => ttJob("restart"));
    $("#tt-logs").addEventListener("click", ttLogs);
    $("#tt-refresh").addEventListener("click", loadTerraTAK);
    $("#tt-remove").addEventListener("click", () => ttJob("remove", null, "Remove the TerraTAK container?\n\nThe data volume (tilesets, database) is kept; installing an image again brings it all back.", true));
    $("#tt-remove-data").addEventListener("click", () => ttJob("remove-data", null, "DELETE the TerraTAK container AND its data volume?\n\nEvery tileset and the database are gone for good.", true));
    $("#tt-install-engine").addEventListener("click", () => ttJob("install-engine", null, "Install Docker on this server?\n\nDebian/Ubuntu: apt-get install docker.io\nRHEL/Rocky: Docker CE from download.docker.com\nThen: systemctl enable --now docker\n\nContinue?", true));
    $("#tt-save").addEventListener("click", () => saveTTSettings(false));
    $("#tt-auth-clear").addEventListener("click", () => { if (confirm("Remove the TerraTAK login?\n\nAfter the next install or upgrade anyone who reaches the port can use and change it.")) saveTTSettings(true); });
    $$("#tt-card input").forEach(el => el.addEventListener("input", () => { el.dataset.touched = "1"; }));
  }

  // ── Certificates: actions ──────────────────────────
  function switchSigner(to) {
    const root = certs && certs.root ? certs.root.name : "the root CA";
    const inter = certs && certs.intermediate ? certs.intermediate.name : "the intermediate CA";
    const msg = to === "root"
      ? `Sign TAK Server's certificate with the root CA (${root})?\n\n• Enrolled devices keep working; TAK Server restarts and they reconnect in about a minute\n• Afterwards, rotating the intermediate CA no longer disconnects every device\n• If this server federates, peers must trust this root CA\n• The current certificate is backed up first and restored if anything fails`
      : `Sign TAK Server's certificate with the intermediate CA (${inter})?\n\n• Devices enrolled on ${inter} keep working; TAK Server restarts and they reconnect in about a minute\n• Devices still on an older intermediate are disconnected\n• Afterwards, rotating the intermediate CA disconnects every device until it re-enrolls\n• The current certificate is backed up first and restored if anything fails`;
    startCertJob("signer", { signer: to }, msg, true);
  }

  function rotateIntCA() {
    const name = $("#rot-name").value.trim();
    if (!name) { alert("Enter a name for the new intermediate CA."); return; }
    if (!/^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$/.test(name)) { alert("CA names: letters, numbers, hyphens and dots only, no spaces or underscores."); return; }
    const days = parseInt($("#rot-days").value, 10) || 730;
    const newPw = $("#rot-pass").value.trim();
    const rootSigned = certs && certs.server && certs.server.mode === "root";
    const reissue = $("#rot-reissue").checked;
    const head = `Create intermediate CA "${name}", reissue the server certificate${reissue ? " and the client certificates on this server" : ""}, and restart TAK Server.\n\n`;
    const tail = rootSigned
      ? "The server certificate stays signed by the root CA, so devices keep connecting. Users then re-enroll or import the new truststore at their own pace.\n\nContinue?"
      : "⚠ EVERY DEVICE WILL DISCONNECT until it re-enrolls: the server certificate is signed by the intermediate CA and no device trusts the new one yet.\n\nTo avoid this, cancel and use \"Switch to root-signed\" first.\n\nRotate anyway?";
    const body = { new_name: name, days, reissue_clients: $("#rot-reissue").checked };
    if (newPw) body.new_password = newPw;
    startCertJob("rotate-intca", body, head + tail, true);
  }

  function revokeCA(alias, cn) {
    let extra = "";
    if (liveRows && liveRows.counts) {
      const n = liveRows.counts[(cn || alias).toLowerCase()] || 0;
      extra = n ? `\n\n${n} live certificate(s) in TAK's table were signed by it and will stop working.` : "\n\nNo live certificates in TAK's table were signed by it.";
    } else {
      extra = "\n\nTip: load \"Live certificates by CA\" first to see who is still on it.";
    }
    startCertJob("revoke", { alias },
      `REVOKE "${alias}" (${cn}) from TAK Server's trust list?\n\nEvery client whose certificate was signed by it is disconnected and must re-enroll. Root CAs leave the trust list too, so nothing gets back in through ${alias}.${extra}\n\nThis cannot be undone.`, true);
  }

  function rotateRootCA() {
    const newRoot = $("#root-name").value.trim();
    const newInt = $("#root-int-name").value.trim();
    if (!newRoot || !newInt) { alert("Enter names for both the new root CA and the new intermediate CA."); return; }
    const re = /^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$/;
    if (!re.test(newRoot) || !re.test(newInt)) { alert("CA names: letters, numbers, hyphens and dots only, no spaces or underscores."); return; }
    if (!confirm(`⚠ FULL ROOT CA ROTATION ⚠\n\n• New root CA: ${newRoot}\n• New intermediate CA: ${newInt}\n• Server and client certificates recreated\n• TAK Server restarted\n\nALL connected devices are disconnected and must re-enroll or import the new truststore.\n\nContinue?`)) return;
    if (!confirm("FINAL CONFIRMATION\n\nThe old PKI is moved to a backup folder and replaced. Do this in a maintenance window.\n\nProceed?")) return;
    const body = { new_root: newRoot, new_int: newInt, root_days: parseInt($("#root-days").value, 10) || 3652, int_days: parseInt($("#root-int-days").value, 10) || 730 };
    const pw = $("#root-pass").value.trim();
    if (pw) body.new_password = pw;
    startCertJob("rotate-root", body, null, true);
  }

  function createClient() {
    const name = $("#client-name").value.trim();
    if (!name) { alert("Enter a name for the client certificate."); return; }
    startCertJob("client", { name }, `Create client certificate "${name}" signed by the current intermediate CA?`, false);
  }

  function setupCerts() {
    $("#btn-certs-refresh").addEventListener("click", loadCerts);
    $("#ca-pass-toggle").addEventListener("click", () => { passShown = !passShown; renderPassword(); });
    $("#fqdn-save").addEventListener("click", saveSettings);
    $("#btn-rotate").addEventListener("click", rotateIntCA);
    $("#btn-root").addEventListener("click", rotateRootCA);
    $("#btn-client").addEventListener("click", createClient);
    $("#btn-live").addEventListener("click", loadLive);
    $("#live-search").addEventListener("input", renderLive);
    $("#btn-snap-save").addEventListener("click", saveSnapshot);
    $("#btn-snap-refresh").addEventListener("click", loadSnapshots);
    $("#snap-name").addEventListener("keydown", (e) => { if (e.key === "Enter") saveSnapshot(); });
    $("#btn-rotate").classList.add("job-btn");
    $("#btn-root").classList.add("job-btn");
    $("#btn-client").classList.add("job-btn");
  }

  // ── Init ───────────────────────────────────────────
  async function init() {
    term.init();
    setupUpload();
    setupActions();
    setupCerts();
    setupPortal();
    setupTerraTAK();
    await fetchPlatform();
    refreshFiles();
    refreshStatus();
    loadSettings();
    loadCerts();
    loadSnapshots();
    loadPortalInfo();
    loadTerraTAK();
    setInterval(refreshStatus, 15000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
