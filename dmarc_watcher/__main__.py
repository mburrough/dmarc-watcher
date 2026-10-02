"""CLI entry point. With no arguments, starts the tray app."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from pathlib import Path

from . import config
from .fetch import (PLACEHOLDER_USERS, FetchError, ImapSource, build_source,
                    collect)
from .parser import parse_any
from .store import Store


def _envelope(row) -> str:
    """Render envelope identifiers, tolerating rows and reports that lack them.

    Many reporters omit envelope_to, and rows written before these columns
    existed have NULL, so an absent value is normal rather than an error.
    """
    keys = row.keys() if hasattr(row, "keys") else []
    bits = []
    for label, key in (("envelope_from", "envelope_from"), ("envelope_to", "envelope_to")):
        if key in keys and row[key]:
            bits.append(f"{label}={row[key]}")
    return "  ".join(bits)


def _print_summary(store: Store, days: int) -> int:
    s = store.summary(days)
    print(f"Last {days} days: {s.short()}")
    print(f"  reports {s.reports_total} ({s.reports_clean} clean)"
          f"  messages {s.messages_total}"
          f"  failing {s.messages_failed}"
          f"  enforced {s.messages_enforced}")
    failures = store.recent_failures(days)
    if failures:
        print("\nFailures:")
        for row in failures:
            print(f"  {row['org_name']:20} {row['source_ip']:16} x{row['count']:<4}"
                  f" disp={row['disposition']:10} dkim={row['dkim_aligned']:5}"
                  f" spf={row['spf_aligned']:5} from={row['header_from']}")
            # The authenticating domain distinguishes an unauthorised sender
            # from one that authenticated under its own domain and merely
            # failed alignment. Different problems, different fixes.
            try:
                auth = json.loads(row["auth"]) or []
            except (TypeError, ValueError):
                auth = []
            print(f"      auth: {'; '.join(auth) if auth else '(none reported)'}")
            # NULL on rows stored before these columns existed.
            env = _envelope(row)
            if env:
                print(f"      {env}")
    # Non-zero exit when something failed, so this is usable from a scheduler.
    return 1 if s.messages_failed else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dmarc-watcher",
                                 description="Monitor DMARC aggregate reports.")
    ap.add_argument("--check", action="store_true",
                    help="fetch once, print a summary, exit")
    ap.add_argument("--summary", action="store_true",
                    help="print the stored summary without fetching")
    ap.add_argument("--import-dir", metavar="DIR",
                    help="import report files from a directory")
    ap.add_argument("--list-folders", action="store_true",
                    help="list IMAP folders (find the right folder name)")
    ap.add_argument("--set-password", action="store_true",
                    help="store the IMAP password in Windows Credential Manager")
    ap.add_argument("--days", type=int, help="window for summaries")
    ap.add_argument("--destinations", action="store_true",
                    help="group traffic by recipient domain (envelope_to)")
    ap.add_argument("--backfill", action="store_true",
                    help="re-read the folder and fill envelope columns on "
                         "records stored before they were captured")
    ap.add_argument("--resync", action="store_true",
                    help="forget IMAP UID pointers and re-read the whole "
                         "folder (duplicates are skipped on the way in)")
    args = ap.parse_args(argv)

    # Without a handler the parser's warnings about unreadable reports
    # are discarded, which is the exact failure mode they exist to report.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s",
                        stream=sys.stderr)

    cfg = config.load_config()
    days = (args.days if args.days is not None
            else int(cfg["general"].get("summary_days", 30)))

    if args.set_password:
        user = cfg["imap"].get("user")
        if not user:
            print("Set imap.user in the config first:", cfg["_config_path"],
                  file=sys.stderr)
            return 2
        if user in PLACEHOLDER_USERS:
            print(f"imap.user is still the example placeholder ({user!r}).\n"
                  f"Edit {cfg['_config_path']} and set it to the address shown "
                  f"in the Proton Bridge window first.", file=sys.stderr)
            return 2
        pw = getpass.getpass(f"IMAP password for {user}: ")
        config.set_password(user, pw)
        print(f"Stored password for {user} in Credential Manager.")
        return 0

    store = Store(config.db_path())
    try:
        if args.destinations:
            rows = store.destinations(days)
            if not rows:
                print(f"No records in the last {days} days.")
                return 0
            print(f"Destinations, last {days} days:")
            for row in rows:
                flag = "   <-- FAILING" if row["failed"] else ""
                print(f"  {row['dest']:28} {row['msgs']:5} msgs,"
                      f" {row['failed']} failed{flag}")
            print("\nA destination showing both passes and failures is usually a"
                  "\nforwarder re-presenting your mail, not mail you cannot deliver.")
            return 0

        if args.backfill:
            # Never flag mail as read while re-reading it for a backfill.
            cfg["imap"] = dict(cfg["imap"], mark_read="never")
            try:
                source = build_source(cfg, store)
                updated = scanned = 0
                with source.session():
                    for msg in source.fetch_all():
                        for name, payload in msg.attachments:
                            for rep in parse_any(payload, name):
                                scanned += 1
                                updated += store.backfill_envelopes(rep)
            except FetchError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print(f"Re-read {scanned} report(s); filled envelope fields on "
                  f"{updated} record(s).")
            return 0

        if args.resync:
            n = store.reset_imap_state()
            print(f"Cleared {n} UID pointer(s). The next --check re-reads "
                  f"the whole folder.")
            return 0

        if args.list_folders:
            try:
                for name in ImapSource(cfg["imap"], store).list_folders():
                    print(name)
            except FetchError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            return 0

        if args.import_dir:
            d = Path(args.import_dir)
            if not d.is_dir():
                print(f"error: not a directory: {d}", file=sys.stderr)
                return 2
            added = dupes = 0
            problems: list[str] = []
            for f in sorted(d.iterdir()):
                if not f.is_file() or f.suffix.lower() not in (".zip", ".gz", ".xml"):
                    continue
                for rep in parse_any(f.read_bytes(), f.name, problems=problems):
                    if store.add_report(rep):
                        added += 1
                    else:
                        dupes += 1
            print(f"Imported {added} report(s), skipped {dupes} already seen.")
            if problems:
                print(f"{len(problems)} file(s) could not be read:", file=sys.stderr)
                for prob in problems:
                    print(f"  {prob}", file=sys.stderr)
            return _print_summary(store, days)

        if args.summary:
            return _print_summary(store, days)

        if args.check:
            try:
                res = collect(build_source(cfg, store), store)
            except FetchError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            note = f", marked {res.marked_read} read" if res.marked_read else ""
            print(f"Fetched {len(res.new_reports)} new report(s), "
                  f"{res.duplicates} already seen{note}.")
            if res.unparseable_messages:
                print(f"warning: {res.unparseable_messages} message(s) held no "
                      f"readable report (left unread)", file=sys.stderr)
            return _print_summary(store, days)
    finally:
        store.close()

    from .app import run_tray
    return run_tray()


if __name__ == "__main__":
    sys.exit(main())
