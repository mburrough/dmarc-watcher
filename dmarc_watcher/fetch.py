"""Report sources: IMAP (Proton Mail Bridge or any server) and a local folder."""

from __future__ import annotations

import email
import imaplib
import ssl
from contextlib import contextmanager
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path

from .parser import Report, parse_any
from .store import Store

# Proton Bridge advertises a locally-generated certificate. Bridge listens only
# on loopback, so the connection cannot be intercepted off-host; we relax
# verification for that case only (see verify_cert in the config).
_ATTACHMENT_HINTS = (".zip", ".gz", ".xml")


class FetchError(RuntimeError):
    pass


class TransientFetchError(FetchError):
    """A failure expected to clear on its own, rather than one needing a fix.

    Mostly Proton Bridge not being up yet: both this app and Bridge usually
    live in the Startup folder, Windows launches them together, and Bridge
    needs time to sign in before it listens. Callers retry these quickly and
    quietly instead of alerting.
    """


# Shipped in config.example.toml; catching these stops a copied-but-unedited
# config from reaching Bridge and burning login attempts against a bad name.
PLACEHOLDER_USERS = {"you@example.com", "user@example.com",
                     "you@yourdomain.example"}


def _login_error(raw: str, user: str) -> FetchError:
    """Translate an IMAP/Bridge error into the action that fixes it.

    Returns TransientFetchError for conditions that resolve without the user
    doing anything, and plain FetchError for ones needing a config change.
    """
    low = raw.lower()
    if "no such user" in low:
        return FetchError(
            f"Bridge does not recognise {user!r}. Use the exact address shown "
            f"in the Proton Bridge window (select your account -> Mailbox "
            f"details / Configure), set it as imap.user, then re-run "
            f"--set-password for that address.")
    if "authentication failed" in low or "invalid credentials" in low or "incorrect" in low:
        return FetchError(
            f"Bridge rejected the password for {user!r}. Use the "
            f"Bridge-specific password from the Bridge window, not your "
            f"Proton account password: re-run --set-password.")
    if "too many login attempts" in low:
        return TransientFetchError(
            "Bridge is rate-limiting after failed logins. It clears on its "
            "own; restarting Proton Bridge clears it immediately.")
    if ("10061" in raw or "refused" in low or "10060" in raw
            or "timed out" in low or "reset" in low or "10054" in raw):
        return TransientFetchError(
            "Proton Bridge is not accepting connections yet. If it is running, "
            "check the port under Bridge Settings -> Connection mode.")
    return FetchError(raw)


def _attachment_parts(msg: Message):
    """Yield (filename, payload) for parts that could hold a DMARC report."""
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename() or ""
        ctype = (part.get_content_type() or "").lower()
        looks_right = (
            filename.lower().endswith(_ATTACHMENT_HINTS)
            or "zip" in ctype or "gzip" in ctype or ctype == "application/xml"
            or ctype == "text/xml"
        )
        if not looks_right:
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if payload:
            yield filename or ctype, payload


@dataclass
class FetchedMessage:
    """One source message. uid is None for non-IMAP sources."""
    uid: int | None
    attachments: list[tuple[str, bytes]] = field(default_factory=list)


MARK_READ_MODES = ("all", "clean", "never")


class ImapSource:
    """Pulls new messages by UID. Bodies are read with BODY.PEEK so the \\Seen
    flag is only ever set deliberately, by mark_read_uids()."""

    def __init__(self, cfg: dict, store: Store):
        self.host = cfg.get("host", "127.0.0.1")
        self.port = int(cfg.get("port", 1143))
        self.user = cfg.get("user", "")
        self.folder = cfg.get("folder", "Folders/DMARC")
        self.security = cfg.get("security", "starttls").lower()
        self.verify_cert = bool(cfg.get("verify_cert", False))
        self.password = cfg.get("_password", "")
        self.mark_read = str(cfg.get("mark_read", "never")).lower()
        if self.mark_read not in MARK_READ_MODES:
            raise FetchError(
                f"imap.mark_read must be one of {MARK_READ_MODES}, "
                f"got {self.mark_read!r}")
        self.store = store
        self._conn: imaplib.IMAP4 | None = None

    def _preflight(self) -> None:
        """Fail on bad config before touching the network, so a misconfigured
        username never consumes Bridge's login-attempt budget."""
        if not self.user:
            raise FetchError("imap.user is not set. Put your Proton address in "
                             "the config, then run --set-password.")
        if self.user in PLACEHOLDER_USERS:
            raise FetchError(
                f"imap.user is still the example placeholder ({self.user!r}). "
                f"Replace it with the address shown in the Proton Bridge window, "
                f"then re-run --set-password for that address.")
        if not self.password:
            raise FetchError(
                f"No password stored for {self.user!r}. Run --set-password "
                f"(the keyring entry is per-username, so changing imap.user "
                f"means storing the password again).")

    def _connect(self) -> imaplib.IMAP4:
        self._preflight()
        ctx = ssl.create_default_context()
        if not self.verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            if self.security == "ssl":
                conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx)
            else:
                conn = imaplib.IMAP4(self.host, self.port)
                if self.security == "starttls":
                    conn.starttls(ctx)
            conn.login(self.user, self.password)
            return conn
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            raise _login_error(str(exc), self.user) from exc

    def list_folders(self) -> list[str]:
        conn = self._connect()
        try:
            typ, data = conn.list()
            if typ != "OK":
                raise FetchError("LIST failed")
            out = []
            for raw in data:
                line = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                # tail of: (\HasNoChildren) "/" "Folders/DMARC"
                out.append(line.rsplit(" ", 1)[-1].strip().strip('"'))
            return out
        finally:
            self._logout(conn)

    @staticmethod
    def _logout(conn: imaplib.IMAP4) -> None:
        try:
            conn.logout()
        except Exception:
            pass

    def _uid_state_keys(self) -> tuple[str, str]:
        base = f"imap:{self.host}:{self.port}:{self.folder}"
        return base + ":uidvalidity", base + ":lastuid"

    @contextmanager
    def session(self):
        """One connection for the whole fetch-then-flag cycle.

        Setting \\Seen needs a read-write SELECT, so the mailbox is only opened
        writable when marking is actually enabled.
        """
        conn = self._connect()
        self._conn = conn
        try:
            folder = self.folder if " " not in self.folder else '"' + self.folder + '"'
            self._folder_arg = folder
            typ, data = conn.select(folder, readonly=(self.mark_read == "never"))
            if typ != "OK":
                detail = data[0].decode(errors="replace") if data and data[0] else "unknown"
                raise FetchError(f"Cannot open folder {self.folder!r}: {detail}")
            yield self
        finally:
            self._conn = None
            self._logout(conn)

    def _require_conn(self) -> imaplib.IMAP4:
        if self._conn is None:
            raise FetchError("IMAP operations must run inside session()")
        return self._conn

    def fetch_new(self) -> list[FetchedMessage]:
        conn = self._require_conn()

        # Prefer the untagged UIDVALIDITY from SELECT; some servers refuse
        # STATUS on the currently-selected mailbox.
        uidvalidity = ""
        untagged = conn.untagged_responses.get("UIDVALIDITY")
        if untagged:
            raw_uv = untagged[0]
            uidvalidity = (raw_uv.decode(errors="replace")
                           if isinstance(raw_uv, (bytes, bytearray)) else str(raw_uv)).strip()
        if not uidvalidity:
            typ, uv = conn.status(self._folder_arg, "(UIDVALIDITY)")
            if typ == "OK" and uv and uv[0]:
                text = uv[0].decode(errors="replace")
                if "UIDVALIDITY" in text:
                    uidvalidity = text.split("UIDVALIDITY", 1)[1].strip(" ()").split()[0]

        uv_key, uid_key = self._uid_state_keys()
        # A changed UIDVALIDITY invalidates every stored UID; rescan the folder.
        if uidvalidity and self.store.get_state(uv_key) != uidvalidity:
            self.store.set_state(uv_key, uidvalidity)
            self.store.set_state(uid_key, "0")
        last_uid = int(self.store.get_state(uid_key, "0") or 0)

        typ, resp = conn.uid("SEARCH", None, f"(UID {last_uid + 1}:*)")
        if typ != "OK":
            raise FetchError("UID SEARCH failed")
        # "UID n:*" always returns the final message even when its UID < n,
        # so filter explicitly rather than trusting the server's range.
        uids = [int(u) for u in resp[0].split() if int(u) > last_uid]

        out: list[FetchedMessage] = []
        highest = last_uid
        for uid in sorted(uids):
            typ, msg_data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            raw = msg_data[0][1]
            if not isinstance(raw, (bytes, bytearray)):
                continue
            msg = email.message_from_bytes(bytes(raw))
            out.append(FetchedMessage(uid=uid,
                                      attachments=list(_attachment_parts(msg))))
            highest = max(highest, uid)

        if highest > last_uid:
            self.store.set_state(uid_key, str(highest))
        return out

    def mark_read_uids(self, uids: list[int]) -> int:
        """Set \\Seen on the given UIDs. Returns how many were flagged."""
        wanted = sorted({u for u in uids if u is not None})
        if not wanted or self.mark_read == "never":
            return 0
        conn = self._require_conn()
        seq = ",".join(str(u) for u in wanted)
        typ, _ = conn.uid("STORE", seq, "+FLAGS", "(\\Seen)")
        if typ != "OK":
            raise FetchError(f"Could not set \\Seen on UIDs {seq}")
        return len(wanted)


class FolderSource:
    """Watches a directory of saved report files. Used for testing, or when
    reports are exported by hand instead of pulled over IMAP."""

    def __init__(self, cfg: dict, store: Store):
        self.path = Path(cfg.get("path", "."))
        self.mark_read = "never"        # nothing to flag on a filesystem
        self.store = store

    @contextmanager
    def session(self):
        yield self

    def fetch_new(self) -> list[FetchedMessage]:
        if not self.path.is_dir():
            raise FetchError(f"Watch folder not found: {self.path}")
        out: list[FetchedMessage] = []
        for f in sorted(self.path.iterdir()):
            if f.is_file() and f.suffix.lower() in (".zip", ".gz", ".xml"):
                out.append(FetchedMessage(uid=None,
                                          attachments=[(f.name, f.read_bytes())]))
        return out

    def mark_read_uids(self, uids: list[int]) -> int:
        return 0


def build_source(cfg: dict, store: Store):
    mode = cfg.get("source", {}).get("mode", "imap").lower()
    if mode == "imap":
        return ImapSource(cfg.get("imap", {}), store)
    if mode == "folder":
        return FolderSource(cfg.get("folder", {}), store)
    raise FetchError(f"Unknown source mode: {mode!r} (expected 'imap' or 'folder')")


@dataclass
class CollectResult:
    new_reports: list[Report] = field(default_factory=list)
    duplicates: int = 0
    marked_read: int = 0
    problems: list[str] = field(default_factory=list)
    unparseable_messages: int = 0


def collect(source, store: Store) -> CollectResult:
    """Fetch, parse and store, then flag processed mail if configured."""
    result = CollectResult()
    new_reports = result.new_reports
    to_mark: list[int] = []

    with source.session():
        for msg in source.fetch_new():
            parsed: list[Report] = []
            for name, payload in msg.attachments:
                parsed.extend(parse_any(payload, name, problems=result.problems))

            # Messages that yielded no report stay unread on purpose: it means
            # something that is not a DMARC report matched the mail rule, and
            # that is worth noticing rather than silently burying. The UID
            # pointer still advances, so this is counted and surfaced.
            if not parsed:
                result.unparseable_messages += 1
                if not msg.attachments:
                    result.problems.append(
                        f"message uid={msg.uid}: no report-like attachment")
                continue

            for rep in parsed:
                if store.add_report(rep):
                    new_reports.append(rep)
                else:
                    result.duplicates += 1

            # Flag only after the reports are committed to the database, so a
            # crash mid-run can never leave a report read but unrecorded.
            if msg.uid is None:
                continue
            if source.mark_read == "all":
                to_mark.append(msg.uid)
            elif source.mark_read == "clean" and all(r.is_clean for r in parsed):
                to_mark.append(msg.uid)

        result.marked_read = source.mark_read_uids(to_mark)

    return result
