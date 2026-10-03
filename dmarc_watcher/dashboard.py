"""A small local dashboard, served to the browser.

Tkinter is not an option here: Tk must own the main thread and pystray's
message loop already does. So the dashboard is served over loopback and opened
in the default browser instead.

Security: binds 127.0.0.1 on an ephemeral port, and every request must carry an
unguessable token generated at startup. Nothing is reachable off the machine,
and another local process cannot guess the URL.
"""

from __future__ import annotations

import html
import json
import logging
import secrets
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

log = logging.getLogger("dmarc-watcher.dashboard")

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root {
    --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --muted:#616b76; --line:#dfe3e8;
    --ok:#1f7a4d; --bad:#b3261e; --warn:#8a5a00; --accent:#2f5bd7;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171a; --card:#1c2126; --fg:#e8eaed; --muted:#9aa4af;
            --line:#2c333a; --ok:#5bd49a; --bad:#ff8a80; --warn:#e0b04a;
            --accent:#8ab0ff; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 "Segoe UI", system-ui, sans-serif; padding:24px 16px; }
  .wrap { max-width:1060px; margin:0 auto; }
  h1 { font-size:20px; margin:0 0 2px; }
  .sub { color:var(--muted); margin-bottom:20px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:12px; margin-bottom:22px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:14px 16px; }
  .card .n { font-size:26px; font-weight:600; }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase;
             letter-spacing:.04em; }
  .state-ok .n { color:var(--ok); } .state-bad .n { color:var(--bad); }
  h2 { font-size:15px; margin:26px 0 10px; }
  table { width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line);
           vertical-align:top; }
  th { background:color-mix(in srgb, var(--card) 85%, var(--fg) 6%);
       font-size:12px; text-transform:uppercase; letter-spacing:.04em;
       color:var(--muted); }
  tr:last-child td { border-bottom:none; }
  code { font:12px/1.4 Consolas, ui-monospace, monospace; color:var(--muted);
         word-break:break-all; }
  .bad { color:var(--bad); font-weight:600; }
  .ok  { color:var(--ok); font-weight:600; }
  .empty { background:var(--card); border:1px solid var(--line); border-radius:10px;
           padding:26px; text-align:center; color:var(--muted); }
  button { font:inherit; border-radius:7px; border:1px solid var(--line);
           background:var(--card); color:var(--fg); padding:7px 13px;
           cursor:pointer; }
  button.primary { background:var(--accent); border-color:var(--accent);
                   color:#fff; }
  button:disabled { opacity:.5; cursor:default; }
  .bar { display:flex; gap:9px; align-items:center; margin:12px 0; flex-wrap:wrap; }
  .note { color:var(--muted); font-size:12px; }
  input[type=text] { font:inherit; padding:7px 9px; border-radius:7px;
                     border:1px solid var(--line); background:var(--bg);
                     color:var(--fg); }
  @media (max-width:640px) { body{padding:16px;} th,td{padding:7px 8px;} }
</style></head>
<body><div class="wrap">
<h1>__TITLE__</h1>
<div class="sub">__SUB__</div>
<div class="cards">__CARDS__</div>

<h2>Unacknowledged failures</h2>
<div class="bar">
  <button id="all">Select all</button>
  <button id="none">Clear</button>
  <input type="text" id="note" placeholder="note (optional), e.g. known forwarder">
  <button class="primary" id="ack" disabled>Acknowledge selected</button>
</div>
<div class="note">Acknowledging keeps the record but stops it counting toward the
tray state. Use a mute when the same benign source will recur.</div>
__FAILURES__

<h2>Mutes</h2>
<div class="note">A mute auto-acknowledges matching failures, now and in future.
Leave a field blank to match anything.</div>
<div class="bar">
  <input type="text" id="m_ip" placeholder="source IP (blank = any)">
  <input type="text" id="m_to" placeholder="destination (blank = any)">
  <input type="text" id="m_note" placeholder="why">
  <button id="addmute">Add mute</button>
</div>
__MUTES__

<h2>Destinations</h2>
__DESTS__
</div>
<script>
const TOKEN = "__TOKEN__";
const boxes = () => [...document.querySelectorAll(".pick")];
function sync() {
  const n = boxes().filter(b => b.checked).length;
  const b = document.getElementById("ack");
  b.disabled = n === 0;
  b.textContent = n ? `Acknowledge ${n} selected` : "Acknowledge selected";
}
async function post(action, body) {
  const r = await fetch(`/api/${action}?token=${TOKEN}`, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
  if (!r.ok) { alert("Request failed: " + r.status); return; }
  location.reload();
}
document.addEventListener("change", e => { if (e.target.classList.contains("pick")) sync(); });
document.getElementById("all").onclick = () => { boxes().forEach(b => b.checked = true); sync(); };
document.getElementById("none").onclick = () => { boxes().forEach(b => b.checked = false); sync(); };
document.getElementById("ack").onclick = () => post("ack", {
  ids: boxes().filter(b => b.checked).map(b => Number(b.dataset.id)),
  note: document.getElementById("note").value
});
document.getElementById("addmute").onclick = () => post("mute", {
  source_ip: document.getElementById("m_ip").value,
  envelope_to: document.getElementById("m_to").value,
  note: document.getElementById("m_note").value
});
document.addEventListener("click", e => {
  if (e.target.dataset.unack) post("unack", {ids: [Number(e.target.dataset.unack)]});
  if (e.target.dataset.delmute) post("delmute", {id: Number(e.target.dataset.delmute)});
});
sync();
</script></body></html>
"""


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _when(ts) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def render(store, domain: str, days: int, token: str) -> str:
    summary = store.summary(days)
    failures = store.recent_failures(days, limit=200)
    acked = store.recent_failures(days, limit=200, include_acked=True)
    acked = [r for r in acked if r["acked_at"]]

    state = "state-ok" if summary.healthy else "state-bad"
    cards = "".join([
        f'<div class="card {state}"><div class="n">{summary.messages_failed}</div>'
        f'<div class="l">Unacked failing</div></div>',
        f'<div class="card"><div class="n">{summary.reports_total}</div>'
        f'<div class="l">Reports</div></div>',
        f'<div class="card"><div class="n">{summary.messages_total}</div>'
        f'<div class="l">Messages</div></div>',
        f'<div class="card"><div class="n">{summary.messages_enforced}</div>'
        f'<div class="l">Rejected / quarantined</div></div>',
        f'<div class="card"><div class="n">{len(acked)}</div>'
        f'<div class="l">Acknowledged</div></div>',
    ])

    if failures:
        rows = []
        for r in failures:
            auth = "; ".join(json.loads(r["auth"] or "[]")) or "(none reported)"
            rows.append(
                f'<tr><td><input type="checkbox" class="pick" data-id="{r["id"]}"></td>'
                f'<td>{_when(r["end_ts"])}</td><td>{_esc(r["org_name"])}</td>'
                f'<td><code>{_esc(r["source_ip"])}</code></td>'
                f'<td>{_esc(r["envelope_to"] or "-")}</td>'
                f'<td class="bad">{_esc(r["disposition"])}</td>'
                f'<td><code>{_esc(auth)}</code></td></tr>')
        failures_html = (
            '<table><tr><th></th><th>Date</th><th>Reporter</th><th>Source IP</th>'
            '<th>To</th><th>Disposition</th><th>Authentication</th></tr>'
            + "".join(rows) + "</table>")
    else:
        failures_html = ('<div class="empty">Nothing unacknowledged. '
                         'The tray icon is green.</div>')

    mutes = store.list_mutes()
    if mutes:
        rows = "".join(
            f'<tr><td><code>{_esc(m["source_ip"] or "any")}</code></td>'
            f'<td>{_esc(m["envelope_to"] or "any")}</td>'
            f'<td>{_esc(m["note"])}</td><td>{_when(m["created_at"])}</td>'
            f'<td><button data-delmute="{m["id"]}">Remove</button></td></tr>'
            for m in mutes)
        mutes_html = ('<table><tr><th>Source IP</th><th>Destination</th><th>Note</th>'
                      '<th>Added</th><th></th></tr>' + rows + "</table>")
    else:
        mutes_html = '<div class="empty">No mutes.</div>'

    dests = store.destinations(days)
    if dests:
        rows = "".join(
            f'<tr><td>{_esc(d["dest"])}</td><td>{d["msgs"]}</td>'
            f'<td class="{"bad" if d["failed"] else "ok"}">{d["failed"]}</td></tr>'
            for d in dests)
        dests_html = ('<table><tr><th>Destination</th><th>Messages</th>'
                      '<th>Failed</th></tr>' + rows + "</table>")
    else:
        dests_html = '<div class="empty">No destination data yet.</div>'

    if acked:
        rows = "".join(
            f'<tr><td>{_when(r["end_ts"])}</td><td><code>{_esc(r["source_ip"])}</code></td>'
            f'<td>{_esc(r["envelope_to"] or "-")}</td><td>{_esc(r["ack_note"])}</td>'
            f'<td><button data-unack="{r["id"]}">Un-ack</button></td></tr>'
            for r in acked[:50])
        dests_html += ('<h2>Acknowledged</h2><table><tr><th>Date</th><th>Source IP</th>'
                       '<th>To</th><th>Note</th><th></th></tr>' + rows + "</table>")

    sub = (f"Last {days} days &middot; "
           f"{summary.reports_clean}/{summary.reports_total} reports clean &middot; "
           f"generated {datetime.now():%Y-%m-%d %H:%M}")
    return (PAGE.replace("__TITLE__", _esc(domain))
                .replace("__SUB__", sub)
                .replace("__CARDS__", cards)
                .replace("__FAILURES__", failures_html)
                .replace("__MUTES__", mutes_html)
                .replace("__DESTS__", dests_html)
                .replace("__TOKEN__", token))


class Dashboard:
    """Serves the dashboard on loopback until the app exits."""

    def __init__(self, store, domain: str, days: int, on_change=None):
        self.store = store
        self.domain = domain
        self.days = days
        self.on_change = on_change
        self.token = secrets.token_urlsafe(24)
        self._server: HTTPServer | None = None
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://127.0.0.1:{port}/?token={self.token}"

    def start(self) -> str:
        with self._lock:
            if self._server is None:
                self._server = HTTPServer(("127.0.0.1", 0), self._handler())
                threading.Thread(target=self._server.serve_forever,
                                 daemon=True).start()
                log.info("dashboard listening on %s", self._server.server_address)
        return self.url

    def stop(self) -> None:
        with self._lock:
            if self._server is not None:
                self._server.shutdown()
                self._server.server_close()
                self._server = None

    def open(self) -> str:
        url = self.start()
        webbrowser.open(url)
        return url

    def _handler(self):
        dash = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):      # keep stdout quiet
                log.debug("dashboard %s", fmt % args)

            def _authorised(self) -> bool:
                token = parse_qs(urlparse(self.path).query).get("token", [""])[0]
                return secrets.compare_digest(token, dash.token)

            def _send(self, code, body: bytes, ctype="text/html; charset=utf-8"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                # The page is for this browser only; never let it be cached or
                # embedded somewhere the token could leak.
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if not self._authorised():
                    self._send(403, b"forbidden", "text/plain")
                    return
                html_text = render(dash.store, dash.domain, dash.days, dash.token)
                self._send(200, html_text.encode("utf-8"))

            def do_POST(self):
                if not self._authorised():
                    self._send(403, b"forbidden", "text/plain")
                    return
                length = int(self.headers.get("Content-Length") or 0)
                try:
                    payload = json.loads(self.rfile.read(length) or b"{}")
                except ValueError:
                    self._send(400, b"bad json", "text/plain")
                    return

                action = urlparse(self.path).path.rsplit("/", 1)[-1]
                store = dash.store
                try:
                    if action == "ack":
                        n = store.ack_records([int(i) for i in payload.get("ids", [])],
                                              str(payload.get("note", ""))[:200])
                    elif action == "unack":
                        n = store.unack_records([int(i) for i in payload.get("ids", [])])
                    elif action == "mute":
                        store.add_mute(str(payload.get("source_ip", ""))[:64],
                                       str(payload.get("envelope_to", ""))[:255],
                                       str(payload.get("note", ""))[:200])
                        n = 1
                    elif action == "delmute":
                        n = store.delete_mute(int(payload.get("id", 0)))
                    else:
                        self._send(404, b"unknown action", "text/plain")
                        return
                except (TypeError, ValueError) as exc:
                    self._send(400, str(exc).encode(), "text/plain")
                    return

                if dash.on_change:
                    dash.on_change()
                self._send(200, json.dumps({"changed": n}).encode(),
                           "application/json")

        return Handler
