#!/usr/bin/env python3
"""
recon_server.py — live dashboard + scan launcher for a recon_scan.py project.
Usage: sudo python3 recon_server.py <project_dir> [--host 127.0.0.1] [--port 5000]

The full workflow now lives in the app: paste targets into the dashboard,
hit Start Scan, and hosts populate the list as each one finishes — no need
to run recon_scan.py from the CLI first (though you still can, e.g. for
scripted/headless runs against the same project).

Root/sudo is needed for the same reason recon_scan.py needed it: nmap's
-sS/-sU scans require raw sockets. Run this as root, or set up passwordless
sudo for nmap, or scans kicked off from the dashboard will fail.

Keep recon_common.py AND recon_scan.py in the same directory as this file —
scanning re-uses recon_scan.py's scan/report/notes-generation code directly.
"""
import argparse
import concurrent.futures
import os
import shutil
import sys
import threading
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, jsonify, request, send_from_directory, abort
except ImportError:
    print("[-] Flask not found. Install with: pip install flask --break-system-packages")
    sys.exit(1)

try:
    from recon_common import (
        h, load_manifest, save_manifest, manifest_path, ensure_project_dirs,
        merge_scan_results, render_flag_chips, CSS, log, ok, warn, err, C, G, X, B,
    )
except ImportError:
    print("[-] recon_common.py not found. Keep it in the same directory as recon_server.py")
    sys.exit(1)

try:
    import recon_scan as rs  # reuses scan_target/process_target/render_* — no logic duplicated
except ImportError as e:
    print(f"[-] Could not import recon_scan.py ({e}). Keep it in the same directory as recon_server.py")
    sys.exit(1)

app = Flask(__name__)
PROJECT_DIR = None
MANIFEST_LOCK = threading.Lock()

SCAN_STATE = {
    'running': False, 'total': 0, 'done': 0, 'remaining': [], 'log': [],
    'started_at': None, 'finished_at': None, 'error': None,
}
STATE_LOCK = threading.Lock()


def manifest_mtime():
    mpath = manifest_path(PROJECT_DIR)
    return mpath.stat().st_mtime if mpath.exists() else 0


# ── Background scan job ────────────────────────────────────────────────────────
def run_scan_job(targets, threads, port_args, do_udp):
    with STATE_LOCK:
        SCAN_STATE.update(
            running=True, total=len(targets), done=0, remaining=list(targets),
            log=[f"Starting scan of {len(targets)} host(s) — {threads} thread(s), ports: {port_args}"],
            started_at=datetime.now().isoformat(), finished_at=None, error=None,
        )
    scan_start = datetime.now()
    try:
        work = [(t, PROJECT_DIR, port_args, do_udp) for t in targets]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(rs.process_target, w): w[0] for w in work}
            for fut in concurrent.futures.as_completed(futures):
                host = futures[fut]
                try:
                    result = fut.result()
                except Exception as e:
                    safe = host.replace('/', '_').replace('.', '-')
                    result = {
                        'host': host, 'safe': safe, 'ports': 0, 'exploits': 0,
                        'hostname': '', 'os': '', 'services': [],
                        'scanned_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                    }
                    with STATE_LOCK:
                        SCAN_STATE['log'].append(f"[!] {host}: error — {e}")

                # Merge this one host in immediately so the dashboard can show
                # it as soon as it's done, without waiting for the whole batch.
                with MANIFEST_LOCK:
                    manifest = load_manifest(PROJECT_DIR)
                    manifest = merge_scan_results(manifest, [result])
                    save_manifest(PROJECT_DIR, manifest)

                with STATE_LOCK:
                    SCAN_STATE['done'] += 1
                    if host in SCAN_STATE['remaining']:
                        SCAN_STATE['remaining'].remove(host)
                    SCAN_STATE['log'].append(
                        f"[+] {host}: {result.get('ports', 0)} port(s), "
                        f"{result.get('exploits', 0)} exploit hit(s)"
                    )

        # Refresh the static snapshot + notes summary once the batch is done.
        with MANIFEST_LOCK:
            manifest = load_manifest(PROJECT_DIR)
        all_results = sorted(manifest.values(), key=lambda r: r['host'])
        rs.render_index(all_results, PROJECT_DIR, scan_start)
        rs.render_obsidian_summary(all_results, PROJECT_DIR, scan_start)
        with STATE_LOCK:
            SCAN_STATE['log'].append("Scan complete.")
    except Exception as e:
        with STATE_LOCK:
            SCAN_STATE['error'] = str(e)
            SCAN_STATE['log'].append(f"[-] Scan job failed: {e}")
    finally:
        with STATE_LOCK:
            SCAN_STATE['running'] = False
            SCAN_STATE['finished_at'] = datetime.now().isoformat()


# ── Dashboard ─────────────────────────────────────────────────────────────────
def render_dashboard():
    manifest = load_manifest(PROJECT_DIR)
    results = sorted(manifest.values(), key=lambda r: r['host'])

    total_hosts = len(results)
    total_ports = sum(r.get('ports', 0) for r in results)
    total_exploits = sum(r.get('exploits', 0) for r in results)
    local_count = sum(1 for r in results if r.get('local'))
    proof_count = sum(1 for r in results if r.get('proof'))

    cards = ''
    for r in results:
        safe = r['safe']
        ip = r['host']
        local, proof = bool(r.get('local')), bool(r.get('proof'))
        exploit_badge = (
            f"<div class='exploit-count has-exploits'>&#9889; {r.get('exploits', 0)} exploit hit(s)</div>"
            if r.get('exploits') else
            "<div class='exploit-count no-exploits'>No exploit hits</div>"
        )
        meta_bits = [f"&#128299; {r.get('ports', 0)} ports"]
        if r.get('hostname'):
            meta_bits.append(f"&#127991; {h(r['hostname'])}")
        if r.get('os'):
            meta_bits.append(f"&#128187; {h(r['os'].split('(')[0].strip())}")
        if r.get('services'):
            meta_bits.append(h(', '.join(r['services'][:6])))

        owned_class = ' fully-owned' if (local and proof) else ''
        cards += f"""
<div class='target-card{owned_class}' data-host='{h(ip)}'>
  <a href='/scans/html/{h(safe)}.html' style='text-decoration:none'>
    <div class='target-ip'>{h(ip)}</div>
    <div class='target-meta'>{'  '.join(f"<span>{b}</span>" for b in meta_bits)}</div>
    {exploit_badge}
  </a>
  {render_flag_chips(ip, local, proof, interactive=True)}
</div>"""

    if not results:
        cards = "<p class='empty-msg'>No hosts scanned yet — paste targets above and hit Start Scan.</p>"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconScan — Live Dashboard</title>
{CSS}
<style>
  .scan-field {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: var(--font-mono); padding: 6px 9px; font-size: 12px; }}
  .scan-field:focus {{ outline: none; border-color: var(--cyan); }}
  #scan-targets {{ width: 100%; resize: vertical; }}
  .scan-options {{ display: flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; align-items: center; }}
  .scan-options label {{ font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; }}
  #scan-submit {{ margin-left: auto; background: var(--green); color: #0d1117; border: none; border-radius: 6px; padding: 8px 20px; font-weight: 700; font-size: 13px; cursor: pointer; }}
  #scan-submit:disabled {{ opacity: .5; cursor: default; }}
  #scan-progress {{ display: none; margin-top: 18px; }}
  #scan-log {{ margin-top: 10px; max-height: 150px; overflow-y: auto; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; font-size: 11px; color: var(--muted); font-family: var(--font-mono); white-space: pre-wrap; }}
</style>
</head>
<body>
<header>
  <span class="logo">[recon_scan]</span>
  <span style="color:var(--muted);font-size:13px"><span class="live-dot"></span>&nbsp;Live dashboard &mdash; {h(PROJECT_DIR)}</span>
  <nav><span style="color:var(--muted);font-size:12px;font-family:var(--font-mono)" id="clock"></span></nav>
</header>
<div class="container">
  <h1>Scan Results</h1>
  <p class="subtitle">Check off Local/Proof as you land flags &mdash; saved instantly, synced across tabs.</p>

  <div class="card">
    <div class="card-header"><h2>&#127919; Scan Hosts</h2></div>
    <div class="card-body">
      <form id="scan-form" onsubmit="startScan(event)">
        <textarea id="scan-targets" class="scan-field" rows="4" placeholder="10.10.10.5&#10;10.10.10.0/24&#10;# comments allowed, one target per line"></textarea>
        <div class="scan-options">
          <label>Threads <input id="scan-threads" class="scan-field" type="number" min="1" max="20" value="5" style="width:55px"></label>
          <label>Ports <input id="scan-ports" class="scan-field" type="text" value="-p 1-12000" style="width:170px"></label>
          <label><input id="scan-no-udp" type="checkbox"> Skip UDP</label>
          <button type="submit" id="scan-submit">Start Scan</button>
        </div>
      </form>
      <div id="scan-progress">
        <div class="progress-label"><span id="scan-progress-text"></span><span id="scan-current" style="color:var(--cyan)"></span></div>
        <div class="progress-track"><div class="progress-fill-local" id="scan-progress-fill" style="width:0%"></div></div>
        <pre id="scan-log"></pre>
      </div>
    </div>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="val">{total_hosts}</div><div class="lbl">Hosts</div></div>
    <div class="stat"><div class="val">{total_ports}</div><div class="lbl">Open Ports</div></div>
    <div class="stat"><div class="val" style="color:var(--red)">{total_exploits}</div><div class="lbl">Exploit Hits</div></div>
    <div class="stat"><div class="val" style="color:var(--green)" id="local-stat">{local_count}/{total_hosts}</div><div class="lbl">Local</div></div>
    <div class="stat"><div class="val" style="color:var(--purple)" id="proof-stat">{proof_count}/{total_hosts}</div><div class="lbl">Proof</div></div>
  </div>
  <input class="search-bar" id="search" type="text" placeholder="Filter by IP, hostname, or service..." oninput="filterCards()">
  <div class="toolbar-row">
    <div class="progress-wrap">
      <div class="progress-label"><span>Local</span><span>Proof</span></div>
      <div class="progress-track">
        <div class="progress-fill-local" id="progress-local" style="width:{(local_count/total_hosts*100) if total_hosts else 0:.0f}%"></div>
        <div class="progress-fill-proof" id="progress-proof" style="width:{(proof_count/total_hosts*100) if total_hosts else 0:.0f}%"></div>
      </div>
    </div>
    <label class="hide-completed-toggle">
      <input type="checkbox" id="hide-done" onchange="toggleHideDone()"> Hide fully-owned hosts
    </label>
  </div>
  <div class="grid" id="grid">{cards}</div>
</div>
<footer>recon_scan.py &nbsp;&middot;&nbsp; live via recon_server.py</footer>
<div class="save-toast" id="toast">Saved</div>
<script>
let knownMtime = {manifest_mtime()};
let saving = false;
let scanInProgress = false;

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(showToast._h);
  showToast._h = setTimeout(() => t.classList.remove('show'), 1500);
}}

function setFlag(host, field, value, checkbox) {{
  saving = true;
  const card = checkbox.closest('.target-card');
  fetch('/api/status/' + encodeURIComponent(host), {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{field: field, value: value}})
  }})
  .then(r => {{ if (!r.ok) throw new Error('save failed'); return r.json(); }})
  .then(data => {{
    knownMtime = data.mtime;
    checkbox.closest('.flag-chip').classList.toggle('on', value);
    if (field === 'local') card.dataset.local = value ? '1' : '0';
    if (field === 'proof') card.dataset.proof = value ? '1' : '0';
    card.classList.toggle('fully-owned', card.dataset.local === '1' && card.dataset.proof === '1');
    showToast((value ? 'Marked ' : 'Unmarked ') + field);
    updateStats();
  }})
  .catch(() => {{
    checkbox.checked = !value;
    showToast('Save failed — check the server');
  }})
  .finally(() => {{ saving = false; }});
}}

function updateStats() {{
  const total = document.querySelectorAll('.target-card').length;
  const local = document.querySelectorAll('.flag-chip.on:not(.proof)').length;
  const proof = document.querySelectorAll('.flag-chip.proof.on').length;
  document.getElementById('local-stat').textContent = local + '/' + total;
  document.getElementById('proof-stat').textContent = proof + '/' + total;
  document.getElementById('progress-local').style.width = (total ? Math.round(local/total*100) : 0) + '%';
  document.getElementById('progress-proof').style.width = (total ? Math.round(proof/total*100) : 0) + '%';
}}

function toggleHideDone() {{
  document.getElementById('grid').classList.toggle('hide-done', document.getElementById('hide-done').checked);
}}

function filterCards() {{
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#grid > .target-card').forEach(c => {{
    c.classList.toggle('hidden', !c.textContent.toLowerCase().includes(q));
  }});
}}

function tickClock() {{
  document.getElementById('clock').textContent = new Date().toLocaleString();
}}
setInterval(tickClock, 1000); tickClock();

// ── Scan launcher ────────────────────────────────────────────────────────────
function startScan(evt) {{
  evt.preventDefault();
  const targets = document.getElementById('scan-targets').value;
  if (!targets.trim()) {{ showToast('Enter at least one target'); return; }}
  const threads = parseInt(document.getElementById('scan-threads').value) || 5;
  const ports = document.getElementById('scan-ports').value.trim() || '-p 1-12000';
  const no_udp = document.getElementById('scan-no-udp').checked;

  document.getElementById('scan-submit').disabled = true;
  fetch('/api/scan', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{targets: targets, threads: threads, ports: ports, no_udp: no_udp}})
  }})
  .then(r => {{
    if (!r.ok) return r.json().then(d => {{ throw new Error(d.description || 'failed to start scan'); }});
    return r.json();
  }})
  .then(() => {{
    scanInProgress = true;
    document.getElementById('scan-progress').style.display = 'block';
    pollScanStatus();
  }})
  .catch(e => {{
    showToast('Could not start scan: ' + e.message);
    document.getElementById('scan-submit').disabled = false;
  }});
}}

function renderScanStatus(s) {{
  if (s.total || s.running) document.getElementById('scan-progress').style.display = 'block';
  document.getElementById('scan-progress-text').textContent = s.done + '/' + s.total + ' host(s) scanned';
  document.getElementById('scan-current').textContent = (s.remaining && s.remaining.length && s.running)
    ? ('queued/running: ' + s.remaining.slice(0, 6).join(', ') + (s.remaining.length > 6 ? '…' : ''))
    : '';
  document.getElementById('scan-progress-fill').style.width = (s.total ? Math.round(s.done / s.total * 100) : 0) + '%';
  document.getElementById('scan-log').textContent = (s.log || []).slice(-15).join('\\n');
  document.getElementById('scan-submit').disabled = !!s.running;
}}

function pollScanStatus() {{
  fetch('/api/scan/status').then(r => r.json()).then(s => {{
    renderScanStatus(s);
    if (s.running) {{
      scanInProgress = true;
      setTimeout(pollScanStatus, 1500);
    }} else if (scanInProgress) {{
      scanInProgress = false;
      location.reload();
    }}
  }}).catch(() => {{}});
}}
pollScanStatus(); // resume showing progress if a scan is already running (e.g. after page reload)

// Poll for changes from other tabs / an in-progress scan / a headless
// recon_scan.py run; reload if something changed that we didn't just save.
setInterval(() => {{
  if (saving || scanInProgress) return;
  fetch('/api/hosts').then(r => r.json()).then(data => {{
    if (data.mtime !== knownMtime) location.reload();
  }}).catch(() => {{}});
}}, 8000);
</script>
</body>
</html>"""
    return page


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
@app.route('/index.html')
def dashboard():
    return render_dashboard()


@app.route('/scans/html/<path:filename>')
def serve_report(filename):
    d = PROJECT_DIR / 'scans' / 'html'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename)


@app.route('/scans/nmap/<path:filename>')
def serve_nmap(filename):
    d = PROJECT_DIR / 'scans' / 'nmap'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename)


@app.route('/scans/searchsploit/<path:filename>')
def serve_searchsploit(filename):
    d = PROJECT_DIR / 'scans' / 'searchsploit'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename, mimetype='text/plain')


@app.route('/notes/<path:filename>')
def serve_note(filename):
    d = PROJECT_DIR / 'notes'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename, mimetype='text/plain')


@app.route('/api/hosts')
def api_hosts():
    manifest = load_manifest(PROJECT_DIR)
    return jsonify(hosts=list(manifest.values()), mtime=manifest_mtime())


@app.route('/api/status/<host>', methods=['POST'])
def api_set_status(host):
    data = request.get_json(silent=True) or {}
    field = data.get('field')
    value = bool(data.get('value'))
    if field not in ('local', 'proof'):
        return jsonify(ok=False, description="field must be 'local' or 'proof'"), 400

    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404
        manifest[host][field] = value
        manifest[host][f'{field}_updated_at'] = datetime.now().isoformat() if value else None
        save_manifest(PROJECT_DIR, manifest)
        mtime = manifest_mtime()

    return jsonify(ok=True, host=host, field=field, value=value, mtime=mtime)


@app.route('/api/scan', methods=['POST'])
def api_start_scan():
    data = request.get_json(silent=True) or {}
    raw = data.get('targets', '')
    targets = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith('#')]
    if not targets:
        return jsonify(ok=False, description="No targets provided"), 400

    try:
        threads = max(1, min(20, int(data.get('threads', 5))))
    except (TypeError, ValueError):
        threads = 5
    ports = (data.get('ports') or '-p 1-12000').strip()
    no_udp = bool(data.get('no_udp', False))

    if not shutil.which('nmap'):
        return jsonify(ok=False, description="nmap not found on this server"), 500

    with STATE_LOCK:
        if SCAN_STATE['running']:
            return jsonify(ok=False, description="A scan is already in progress"), 409

    threading.Thread(
        target=run_scan_job, args=(targets, threads, ports, not no_udp), daemon=True
    ).start()
    return jsonify(ok=True, targets=targets)


@app.route('/api/scan/status')
def api_scan_status():
    with STATE_LOCK:
        return jsonify(dict(SCAN_STATE))


def main():
    global PROJECT_DIR
    p = argparse.ArgumentParser(description='Live dashboard + scan launcher for a recon_scan.py project')
    p.add_argument('project', help='Project directory (created automatically if it does not exist)')
    p.add_argument('--host', default='127.0.0.1', help='Bind address (use 0.0.0.0 to reach it from other devices)')
    p.add_argument('--port', type=int, default=5000)
    p.add_argument('--debug', action='store_true', default=False)
    args = p.parse_args()

    PROJECT_DIR = ensure_project_dirs(args.project)

    if not shutil.which('nmap'):
        warn("nmap not found — scans started from the dashboard will fail until it's installed")
    if not shutil.which('searchsploit'):
        warn("searchsploit not found — exploit lookups will be skipped for scans run from here")
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        warn("Not running as root — nmap's SYN/UDP scans need raw sockets. "
             "Run with sudo, or scans from the dashboard may fail or degrade.")

    n_hosts = len(load_manifest(PROJECT_DIR))
    ok(f"Serving {B}{PROJECT_DIR}{X} ({n_hosts} host(s)) at {C}http://{args.host}:{args.port}/{X}")
    if args.host == '0.0.0.0':
        warn("Bound to 0.0.0.0 — reachable from anywhere on your network. No auth is implemented.")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == '__main__':
    main()
