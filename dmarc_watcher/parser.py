"""Parsing of DMARC aggregate (RUA) reports per RFC 7489 Appendix C."""

from __future__ import annotations

import gzip
import io
import logging
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger("dmarc-watcher.parser")

GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"


class NotADmarcReport(ValueError):
    """Well-formed XML that is not a DMARC aggregate report.

    Without this check any XML parses into an empty Report, which then counts
    as a passing report with zero messages -- turning unrelated mail in the
    folder into a false "all clean" signal.
    """


def _strip_namespaces(root: ET.Element) -> ET.Element:
    """Reporters disagree about namespaces: Google and Microsoft send bare XML,
    mail.com sends urn:ietf:params:xml:ns:dmarc-2.0. Strip them so one set of
    element paths works for every reporter."""
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.rsplit("}", 1)[-1]
    return root


def _text(el: ET.Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _int(el: ET.Element | None, path: str, default: int = 0) -> int:
    try:
        return int(_text(el, path))
    except (TypeError, ValueError):
        return default


@dataclass
class AuthResult:
    kind: str           # "dkim" or "spf"
    domain: str
    result: str
    selector: str = ""
    scope: str = ""

    def describe(self) -> str:
        label = self.kind.upper()
        if self.selector:
            label += "[" + self.selector + "]"
        return f"{label} {self.result} ({self.domain or '-'})"


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str        # none | quarantine | reject
    dkim_aligned: str       # policy_evaluated result: pass | fail
    spf_aligned: str
    header_from: str = ""
    envelope_from: str = ""
    envelope_to: str = ""
    reasons: list[tuple[str, str]] = field(default_factory=list)
    auth: list[AuthResult] = field(default_factory=list)

    @property
    def dmarc_pass(self) -> bool:
        """DMARC passes when EITHER aligned mechanism passes."""
        return self.dkim_aligned == "pass" or self.spf_aligned == "pass"

    @property
    def enforced(self) -> bool:
        """Mail the receiver actually quarantined or rejected."""
        return self.disposition in ("quarantine", "reject")

    @property
    def benign_forward(self) -> bool:
        """Failures a forwarder or mailing list explains, not a real spoof."""
        kinds = {k for k, _ in self.reasons}
        return bool(kinds & {"forwarded", "mailing_list", "trusted_forwarder"})

    def summary(self) -> str:
        bits = [f"{self.source_ip} x{self.count}", "disp=" + self.disposition,
                "dkim=" + self.dkim_aligned, "spf=" + self.spf_aligned]
        if self.header_from:
            bits.append("from=" + self.header_from)
        if self.reasons:
            bits.append("reason=" + ",".join(k for k, _ in self.reasons))
        return " ".join(bits)


@dataclass
class Report:
    org_name: str
    report_id: str
    contact_email: str
    begin: int
    end: int
    domain: str
    policy_p: str
    policy_sp: str
    policy_pct: str
    adkim: str
    aspf: str
    records: list[Record] = field(default_factory=list)
    source_name: str = ""

    @property
    def key(self) -> str:
        """Stable dedupe key. report_id is only unique per reporting org."""
        return self.org_name + "!" + self.report_id

    @property
    def begin_dt(self) -> datetime:
        return datetime.fromtimestamp(self.begin, tz=timezone.utc)

    @property
    def end_dt(self) -> datetime:
        return datetime.fromtimestamp(self.end, tz=timezone.utc)

    @property
    def total_messages(self) -> int:
        return sum(r.count for r in self.records)

    @property
    def failed_records(self) -> list[Record]:
        return [r for r in self.records if not r.dmarc_pass]

    @property
    def failed_messages(self) -> int:
        return sum(r.count for r in self.failed_records)

    @property
    def enforced_messages(self) -> int:
        return sum(r.count for r in self.records if r.enforced)

    @property
    def is_clean(self) -> bool:
        return self.failed_messages == 0


def _parse_record(el: ET.Element) -> Record:
    row = el.find("row")
    pe = row.find("policy_evaluated") if row is not None else None
    ident = el.find("identifiers")
    auth_el = el.find("auth_results")

    reasons: list[tuple[str, str]] = []
    if pe is not None:
        for r in pe.findall("reason"):
            reasons.append((_text(r, "type"), _text(r, "comment")))

    auth: list[AuthResult] = []
    if auth_el is not None:
        for d in auth_el.findall("dkim"):
            auth.append(AuthResult("dkim", _text(d, "domain"), _text(d, "result"),
                                   selector=_text(d, "selector")))
        for s in auth_el.findall("spf"):
            auth.append(AuthResult("spf", _text(s, "domain"), _text(s, "result"),
                                   scope=_text(s, "scope")))

    # Absent policy_evaluated children default to "fail" so a malformed report
    # is never silently counted as passing.
    return Record(
        source_ip=_text(row, "source_ip"),
        count=_int(row, "count", 1),
        disposition=_text(pe, "disposition", "none") or "none",
        dkim_aligned=_text(pe, "dkim", "fail") or "fail",
        spf_aligned=_text(pe, "spf", "fail") or "fail",
        header_from=_text(ident, "header_from"),
        envelope_from=_text(ident, "envelope_from"),
        envelope_to=_text(ident, "envelope_to"),
        reasons=reasons,
        auth=auth,
    )


def parse_xml(data: bytes, source_name: str = "") -> Report:
    root = _strip_namespaces(ET.fromstring(data))
    if root.tag != "feedback":
        raise NotADmarcReport(f"root element is <{root.tag}>, expected <feedback>")

    meta = root.find("report_metadata")
    date_range = meta.find("date_range") if meta is not None else None
    pub = root.find("policy_published")
    if meta is None or pub is None:
        raise NotADmarcReport("missing report_metadata or policy_published")
    # A report with no identity cannot be deduplicated (every one of them would
    # collapse onto the same key), and a report with no domain is not about us.
    if not _text(meta, "report_id"):
        raise NotADmarcReport("no report_id")
    if not _text(pub, "domain"):
        raise NotADmarcReport("no policy_published/domain")

    return Report(
        org_name=_text(meta, "org_name", "unknown"),
        report_id=_text(meta, "report_id"),
        contact_email=_text(meta, "email"),
        begin=_int(date_range, "begin"),
        end=_int(date_range, "end"),
        domain=_text(pub, "domain"),
        policy_p=_text(pub, "p"),
        policy_sp=_text(pub, "sp"),
        policy_pct=_text(pub, "pct", "100"),
        adkim=_text(pub, "adkim", "r"),
        aspf=_text(pub, "aspf", "r"),
        records=[_parse_record(r) for r in root.findall("record")],
        source_name=source_name,
    )


def extract_xml_blobs(data: bytes, name: str = "", _depth: int = 0) -> list[tuple[str, bytes]]:
    """Unwrap .zip/.gz containers down to raw XML.

    Dispatches on magic bytes rather than filename: reporters mislabel
    extensions often enough that trusting the name loses reports.
    """
    if _depth > 4:            # guard against nested-archive loops
        return []

    if data.startswith(GZIP_MAGIC):
        try:
            inner = gzip.decompress(data)
        except OSError:
            return []
        return extract_xml_blobs(inner, name.removesuffix(".gz"), _depth + 1)

    if data.startswith(ZIP_MAGIC):
        out: list[tuple[str, bytes]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > 64 * 1024 * 1024:
                        continue
                    out.extend(extract_xml_blobs(zf.read(info), info.filename, _depth + 1))
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return []
        return out

    stripped = data.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<feedback"):
        return [(name, data)]
    return []


def parse_any(data: bytes, name: str = "",
              problems: list[str] | None = None) -> list[Report]:
    """Parse one attachment or file of any supported container type.

    Anything that cannot be parsed is recorded in `problems` and logged rather
    than silently dropped: the UID pointer advances past the source message, so
    a quiet failure here means a report is lost for good.
    """
    def note(detail: str) -> None:
        log.warning("%s: %s", name or "<unnamed>", detail)
        if problems is not None:
            problems.append(f"{name or '<unnamed>'}: {detail}")

    blobs = extract_xml_blobs(data, name)
    if not blobs:
        note("no XML found (not a report, or a corrupt archive)")
        return []

    reports: list[Report] = []
    for blob_name, blob in blobs:
        try:
            reports.append(parse_xml(blob, source_name=blob_name or name))
        except NotADmarcReport as exc:
            note(f"not a DMARC report ({exc})")
        except ET.ParseError as exc:
            note(f"malformed XML ({exc})")
    return reports
