# DMARC Watcher

A Windows system-tray monitor for DMARC aggregate (RUA) reports. It checks a
mail folder on a schedule, parses every report it finds, and stays silent unless
something actually failed.

- **Green check** — all reports in the window are clean
- **Red exclamation** + toast — new reports contain DMARC failures
- **Grey dash** — no reports recently (usually a broken mail rule or Bridge)
- **Amber X** — the check itself failed (Bridge down, wrong folder, bad password)

Hovering the tray icon shows a summary like:

```
example.com
14/14 reports clean (30d)
Last check 15:04
```

## Requirements

- Python 3.11+ (developed against 3.14)
- `pip install -r requirements.txt`
- For Proton: **Proton Mail Bridge**, running and logged in

### The Proton caveat

Proton has no public mail API and no direct IMAP. The only supported way to read
a Proton mailbox programmatically is Proton Mail Bridge, which runs locally and
exposes IMAP on `127.0.0.1:1143`. **Bridge requires a paid Proton plan** (Mail
Plus, Unlimited, or Business). If you are on the free tier, use `folder` mode
below instead.

## Setup

1. In Proton, create a folder named `DMARC` and a rule routing reports into it.
   Filter on subject containing `Report domain:` — that prefix is specified in
   RFC 7489 §7.2.1.1 and every compliant reporter uses it.

2. Copy the config and edit it:

```bash
copy config.example.toml config.toml
```

3. Find the exact IMAP folder name. Proton Bridge exposes custom folders under a
   `Folders/` prefix, so `DMARC` is usually `Folders/DMARC`:

```bash
py -3 -m dmarc_watcher --list-folders
```

4. Store the Bridge password in Windows Credential Manager (it is never written
   to the config file):

```bash
py -3 -m dmarc_watcher --set-password
```

Use the **Bridge-specific password** from the Bridge UI, not your Proton
account password.

5. Test a fetch:

```bash
py -3 -m dmarc_watcher --check
```

6. Run it, and optionally install the Startup shortcut:

```bash
py -3 -m dmarc_watcher
```

```bash
powershell -ExecutionPolicy Bypass -File install-startup.ps1
```

## Startup ordering

If you install the Startup shortcut, Windows launches this app and Proton
Bridge at roughly the same time, and Bridge needs time to sign in before it
listens on its IMAP port. A naive monitor alerts on that every single boot.

Instead, for `startup_grace_minutes` after launch (default 10), a *connection*
failure is treated as "still waiting": grey icon, tooltip reading
`Waiting for Proton Bridge...`, no toast, and a retry every `retry_seconds`
(default 30) rather than the normal hourly poll. The grace period ends early
as soon as any check succeeds.

This applies only to failures that resolve on their own -- Bridge not
listening yet, or its post-failure rate limit. Configuration errors (unknown
user, wrong password, placeholder config) alert immediately, because waiting
would not fix them.

## Uninstalling

```bash
powershell -ExecutionPolicy Bypass -File uninstall.ps1
```

Stops any running instance, removes the Startup shortcut, and deletes the
stored Bridge password from Credential Manager. **Your report database is kept
by default** -- reporters never re-send an aggregate report, so deleting it
destroys history that cannot be rebuilt.

To remove the data too, pass `-RemoveData`; you will be asked to type `DELETE`
to confirm. Add `-Force` to skip the prompt for scripted use. The project
folder itself is never touched.

## Folder mode (no Bridge)

Set `mode = "folder"` and point `folder.path` at a directory. Save report
attachments there by hand, or have any other tool drop them in.

```bash
py -3 -m dmarc_watcher --import-dir C:\path\to\saved-reports
```

## CLI

| Command | What it does |
|---|---|
| *(no args)* | run the tray app |
| `--check` | fetch once, print a summary, exit |
| `--summary` | print stored summary without fetching |
| `--import-dir DIR` | import saved report files |
| `--list-folders` | list IMAP folders |
| `--set-password` | store the IMAP password |
| `--days N` | window for summaries (default 30) |
| `--resync` | forget IMAP UID pointers and re-read the whole folder |

`--check` exits **1** when failures are present, so it also works from Task
Scheduler if you would rather not have a tray app.

## Marking reports read

Bridge is a full IMAP server and supports the `\Seen` flag, which syncs back to
Proton, so a report marked read here shows as read in the Proton web UI too.
Set `mark_read` under `[imap]`:

| Value | Behaviour |
|---|---|
| `never` | leave everything unread (default) |
| `all` | mark every successfully processed report read |
| `clean` | mark only passing reports read, so failures stay bold in the folder |

Bodies are always fetched with `BODY.PEEK[]`, so reading a message never sets
the flag as a side effect — the mailbox is only opened read-write when
`mark_read` is not `never`, and flags are set only *after* the reports are
committed to the database. A crash mid-run can therefore never leave a report
marked read but unrecorded.

A message that produces no parseable report is deliberately left unread: it
means something that is not a DMARC report matched your mail rule, which is
worth noticing rather than silently burying.

## Retention

`retain_days = 0` (the default) keeps every report forever. This matters more
than it looks: reporters never re-send a report, and the IMAP UID pointer means
a deleted report is not re-fetched on the next poll. Pruning is therefore
irreversible — the only recovery is `--resync`, and only while the source mail
still exists in the folder. Set a non-zero value only if you genuinely want
history discarded; it is clamped to at least `summary_days`.

## How failures are decided

A record fails when **neither** aligned mechanism passed:

```python
dmarc_pass = policy_evaluated.dkim == "pass" or policy_evaluated.spf == "pass"
```

DMARC needs only one aligned pass, so a forwarded message with a surviving DKIM
signature and broken SPF counts as a **pass** — it is not flagged. Records
carrying a `forwarded` or `mailing_list` override reason are tracked separately
(`Record.benign_forward`) since those are usually legitimate relaying rather
than spoofing.

Input is validated before it counts. A document is only accepted as a report if
its root element is `<feedback>` and it carries both a `report_id` and a
`policy_published/domain`. Without that check any well-formed XML parses into an
empty report with zero messages, which then reads as a *passing* report — so
unrelated mail landing in the folder would show up as "all clean". Anything
rejected is logged, counted, and left unread in the mailbox.

Note that `disposition: none` on a passing record is normal and not a problem:
it means the receiver took no action because nothing failed.

## Files

- `dmarc_watcher/parser.py` — report parsing; handles `.xml`, `.gz`, `.zip`,
  nested archives, and both namespaced and bare XML
- `dmarc_watcher/store.py` — SQLite dedupe and rollups
- `dmarc_watcher/fetch.py` — IMAP (UID-tracked, `BODY.PEEK` so nothing is
  marked read) and folder sources
- `dmarc_watcher/app.py` — tray icon, polling, notifications
- `dmarc_watcher/icons.py` — icons drawn at runtime, no binary assets
- `install-startup.ps1` / `uninstall.ps1` — Startup shortcut management and
  cleanup

Data lives in `%APPDATA%\dmarc-watcher\` (`reports.db`, `dmarc-watcher.log`).
