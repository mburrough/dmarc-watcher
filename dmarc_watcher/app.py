"""System tray application: poll, classify, notify."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import pystray
from pystray import Menu, MenuItem

from . import config, icons
from .dashboard import Dashboard
from .fetch import FetchError, TransientFetchError, build_source, collect
from .store import Store, Summary

log = logging.getLogger("dmarc-watcher")

# Windows truncates tray tooltips at 127 characters.
TOOLTIP_LIMIT = 127


def setup_logging() -> None:
    path = config.log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(path, maxBytes=512_000, backupCount=2,
                                  encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


class DmarcTray:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.general = cfg["general"]
        self.summary_days = int(self.general.get("summary_days", 30))
        self.poll_seconds = max(60, int(self.general.get("poll_minutes", 60)) * 60)
        self.stale_days = int(self.general.get("stale_days", 10))
        # 0 = keep every report forever. Anything shorter than the summary
        # window would delete rows the tooltip still needs, so clamp it.
        self.retain_days = int(self.general.get("retain_days", 0))
        if 0 < self.retain_days < self.summary_days:
            log.warning("retain_days (%d) < summary_days (%d); raising it",
                        self.retain_days, self.summary_days)
            self.retain_days = self.summary_days
        self.domain = self.general.get("domain") or "DMARC"
        # Bridge and this app usually start together from the Startup folder,
        # and Bridge needs time to sign in. For that window a connection
        # failure is expected, so retry quickly and stay quiet instead of
        # firing a "check failed" toast on every boot.
        self.startup_grace_seconds = max(
            0, int(self.general.get("startup_grace_minutes", 10)) * 60)
        self.retry_seconds = max(10, int(self.general.get("retry_seconds", 30)))

        self.store = Store(config.db_path())
        self.images = icons.all_icons()
        self.state = "unknown"
        self.last_check: datetime | None = None
        self.last_error: str | None = None
        self.last_problems: list[str] = []
        self.waiting_for_source = False
        self.had_success = False
        self.grace_attempts = 0
        self._started_at = time.monotonic()
        self.consecutive_errors = 0
        self._dashboard = Dashboard(self.store, self.domain,
                                    self.summary_days,
                                    on_change=self._on_dashboard_change)
        self._stop = threading.Event()
        self._checking = threading.Lock()

        self.icon = pystray.Icon(
            "dmarc-watcher",
            icon=self.images["unknown"],
            title=f"{self.domain}: starting up",
            menu=self._build_menu(),
        )

    # -- menu -----------------------------------------------------------
    def _build_menu(self) -> Menu:
        return Menu(
            MenuItem(lambda _: self._status_line(), None, enabled=False),
            Menu.SEPARATOR,
            # The dashboard is the default action: clicking the icon is almost
            # always "show me what this state means", not "poll again now".
            MenuItem("Open dashboard…", self._on_details, default=True),
            MenuItem("Check now", self._on_check_now),
            Menu.SEPARATOR,
            MenuItem("Open log", self._on_open_log),
            MenuItem("Quit", self._on_quit),
        )

    def _status_line(self) -> str:
        if self.last_error:
            return f"Error: {self.last_error[:60]}"
        return self.store.summary(self.summary_days).short()

    # -- state ----------------------------------------------------------
    def _classify(self, summary: Summary) -> str:
        if self.waiting_for_source:
            return "unknown"
        if self.last_error:
            return "error"
        if summary.reports_total == 0:
            return "unknown"
        if not summary.healthy:
            return "problem"
        # Reports arriving daily then stopping usually means the mail rule or
        # Bridge broke, which is itself worth surfacing rather than showing green.
        newest = self.store.summary(self.stale_days)
        if newest.reports_total == 0:
            return "unknown"
        return "ok"

    def _refresh_ui(self) -> None:
        summary = self.store.summary(self.summary_days)
        self.state = self._classify(summary)
        self.icon.icon = self.images[self.state]

        stamp = self.last_check.strftime("%H:%M") if self.last_check else "never"
        if self.waiting_for_source:
            body = "Waiting for Proton Bridge…"
        elif self.last_error:
            body = f"Check failed: {self.last_error}"
        elif self.state == "unknown" and summary.reports_total == 0:
            body = f"No reports yet ({self.summary_days}d)"
        elif self.state == "unknown":
            body = f"No reports in {self.stale_days}d - check mail rule"
        else:
            body = summary.short()

        title = f"{self.domain}\n{body}\nLast check {stamp}"
        self.icon.title = title[:TOOLTIP_LIMIT]
        self.icon.update_menu()

    # -- the check ------------------------------------------------------
    def check(self, manual: bool = False) -> None:
        if not self._checking.acquire(blocking=False):
            log.info("check already running, skipping")
            return
        try:
            source = build_source(self.cfg, self.store)
            res = collect(source, self.store)
            new_reports = res.new_reports
            self.last_error = None
            self.consecutive_errors = 0
            self.waiting_for_source = False
            self.had_success = True
            self.grace_attempts = 0
            self.last_check = datetime.now()
            self.last_problems = res.problems

            muted = self.store.apply_mutes()
            if muted:
                log.info("auto-acknowledged %d record(s) by mute rule", muted)
            failing = [r for r in new_reports if not r.is_clean]
            # A mute means "I already know about this source", so a report
            # whose failures were all auto-acknowledged must not re-alert.
            if failing and not self.store.unacked_failures_for(
                    [r.key for r in failing]):
                log.info("all %d new failing report(s) acknowledged by mute",
                         len(failing))
                failing = []
            log.info("check ok: %d new, %d duplicate, %d failing, %d marked read,"
                     " %d unparseable", len(new_reports), res.duplicates,
                     len(failing), res.marked_read, res.unparseable_messages)
            for p in res.problems:
                log.warning("unparsed: %s", p)

            if failing:
                self._notify_failures(failing)
            elif manual or self.general.get("notify_on_clean"):
                s = self.store.summary(self.summary_days)
                self._notify("DMARC all clear", s.short())
        except TransientFetchError as exc:
            self.last_check = datetime.now()
            if self._in_startup_grace():
                # Expected while Bridge comes up: stay grey and quiet. This
                # does NOT advance consecutive_errors, which counts only
                # reportable failures -- otherwise the quiet retries would
                # push the counter past the notify trigger and the first real
                # failure after the grace window would never toast.
                self.waiting_for_source = True
                self.last_error = None
                self.grace_attempts += 1
                log.info("waiting for source, attempt %d (%s), retry in %ds",
                         self.grace_attempts, exc, self.retry_seconds)
            else:
                self.waiting_for_source = False
                self.last_error = str(exc)
                self.consecutive_errors += 1
                log.error("fetch failed: %s", exc)
                if manual or self.consecutive_errors % 6 == 1:
                    self._notify("DMARC check failed", str(exc)[:180])
        except FetchError as exc:
            self.waiting_for_source = False
            self.last_error = str(exc)
            self.consecutive_errors += 1
            self.last_check = datetime.now()
            log.error("fetch failed: %s", exc)
            # Toast the first failure and then hourly-ish, not every poll, so a
            # Bridge outage does not turn into a notification storm.
            if manual or self.consecutive_errors == 1 or self.consecutive_errors % 6 == 0:
                self._notify("DMARC check failed", str(exc)[:180])
        except Exception as exc:                      # noqa: BLE001
            self.last_error = f"{type(exc).__name__}: {exc}"
            self.consecutive_errors += 1
            self.last_check = datetime.now()
            log.exception("unexpected error during check")
            if manual or self.consecutive_errors == 1:
                self._notify("DMARC Watcher error", str(exc)[:180])
        finally:
            self._checking.release()
            # _refresh_ui touches sqlite and the tray icon; if it throws here it
            # would replace whatever actually went wrong with its own traceback.
            try:
                self._refresh_ui()
            except Exception:
                log.exception("failed to refresh tray UI")

    def _in_startup_grace(self) -> bool:
        """True while a transient failure is still explainable by slow startup.

        Ends at the grace deadline, or as soon as one check has succeeded --
        after that, a connection failure is a real outage worth reporting.
        """
        if self.had_success:
            return False
        return (time.monotonic() - self._started_at) < self.startup_grace_seconds

    def _notify_failures(self, failing: list) -> None:
        msgs = sum(r.failed_messages for r in failing)
        enforced = sum(r.enforced_messages for r in failing)
        orgs = ", ".join(sorted({r.org_name for r in failing})[:3])
        lines = [f"{msgs} message(s) failed DMARC in {len(failing)} new report(s).",
                 f"Reported by: {orgs}"]
        if enforced:
            lines.append(f"{enforced} were quarantined or rejected.")
        ips = sorted({rec.source_ip for r in failing for rec in r.failed_records})
        if ips:
            lines.append("Sources: " + ", ".join(ips[:4]))
        self._notify(f"DMARC failures for {self.domain}", "\n".join(lines))

    def _notify(self, title: str, message: str) -> None:
        try:
            self.icon.notify(message, title)
        except Exception:
            log.exception("notification failed")

    # -- menu handlers --------------------------------------------------
    def _on_check_now(self, icon=None, item=None) -> None:
        threading.Thread(target=self.check, kwargs={"manual": True},
                         daemon=True).start()

    def _on_details(self, icon=None, item=None) -> None:
        try:
            self._dashboard.open()
        except Exception:
            log.exception("could not open dashboard; falling back to a text file")
            path = config.app_dir() / "last-details.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self._details_text(), encoding="utf-8")
            self._open(str(path))

    def _on_dashboard_change(self) -> None:
        """Called after an ack or mute, so the icon reflects it at once rather
        than at the next poll."""
        try:
            self._refresh_ui()
        except Exception:
            log.exception("failed to refresh tray after dashboard change")

    def _details_text(self) -> str:
        s = self.store.summary(self.summary_days)
        out = [f"DMARC Watcher - {self.domain}",
               f"Generated {datetime.now():%Y-%m-%d %H:%M}",
               f"Config: {self.cfg.get('_config_path')}",
               "",
               f"Last {s.days} days",
               f"  Reports:            {s.reports_total} ({s.reports_clean} clean)",
               f"  Messages:           {s.messages_total}",
               f"  Failing DMARC:      {s.messages_failed}",
               f"  Quarantined/reject: {s.messages_enforced}",
               ""]

        failures = self.store.recent_failures(self.summary_days)
        out.append("Failures")
        if not failures:
            out.append("  none")
        for row in failures:
            when = datetime.fromtimestamp(row["end_ts"], tz=timezone.utc)
            out.append(
                f"  {when:%Y-%m-%d} {row['org_name']:20} {row['source_ip']:16}"
                f" x{row['count']:<5} disp={row['disposition']:10}"
                f" dkim={row['dkim_aligned']:5} spf={row['spf_aligned']:5}"
                f" from={row['header_from']}")
            try:
                auth = json.loads(row["auth"]) or []
            except (TypeError, ValueError):
                auth = []
            out.append(f"      auth: {'; '.join(auth) if auth else '(none reported)'}")
            keys = row.keys()
            env = "  ".join(f"{k}={row[k]}" for k in ("envelope_from", "envelope_to")
                            if k in keys and row[k])
            if env:
                out.append(f"      {env}")

        out += ["", "Top sending sources"]
        for row in self.store.top_sources(self.summary_days):
            flag = "  <-- FAILING" if row["failed"] else ""
            out.append(f"  {row['source_ip']:16} {row['msgs']:5} msgs,"
                       f" {row['failed']} failed{flag}")

        if self.last_problems:
            out += ["", "Unparsed items from the last check"]
            out += [f"  {p}" for p in self.last_problems]
        if self.last_error:
            out += ["", f"Last error: {self.last_error}"]
        return "\n".join(out) + "\n"

    def _on_open_log(self, icon=None, item=None) -> None:
        self._open(str(config.log_path()))

    @staticmethod
    def _open(path: str) -> None:
        try:
            os.startfile(path)                        # noqa: S606 (Windows only)
        except Exception:
            subprocess.Popen(["notepad.exe", path])

    def _on_quit(self, icon=None, item=None) -> None:
        log.info("quitting")
        self._dashboard.stop()
        self._stop.set()
        self.icon.visible = False
        self.icon.stop()

    # -- lifecycle ------------------------------------------------------
    def _poll_loop(self, icon) -> None:
        icon.visible = True
        self.check()
        while True:
            # Poll fast while still waiting for Bridge, normally otherwise.
            wait = self.retry_seconds if self.waiting_for_source else self.poll_seconds
            if self._stop.wait(wait):
                return
            self.check()
            if self.retain_days > 0:
                removed = self.store.prune(self.retain_days)
                if removed:
                    log.info("pruned %d report(s) older than %d days",
                             removed, self.retain_days)

    def run(self) -> None:
        log.info("starting, polling every %ds", self.poll_seconds)
        self.icon.run(setup=self._poll_loop)
        self.store.close()


def run_tray() -> int:
    setup_logging()
    cfg = config.load_config()
    DmarcTray(cfg).run()
    return 0
