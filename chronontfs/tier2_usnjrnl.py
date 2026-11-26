"""
Tier 2: $UsnJrnl:$J Event Sequence & Transition Delta Filter.

Parses USN Journal records, reconstructs event chains per file (FRN),
and classifies benign archive extraction vs. confirmed timestomping
based on the transition time gap (Δt_finalize).
"""

import struct
import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional

NTFS_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# USN Reason flags
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_CLOSE = 0x80000000

# Combined flags (common during extraction)
USN_REASON_CREATE_EXTEND = 0x00000102

# Default threshold for benign extraction (seconds)
DEFAULT_THRESHOLD_SECONDS = 1.0


def filetime_to_datetime(ft: int) -> Optional[datetime.datetime]:
    if ft == 0:
        return None
    try:
        return NTFS_EPOCH + datetime.timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


@dataclass
class USNRecord:
    """Parsed USN_RECORD_V2 entry."""
    record_length: int = 0
    major_version: int = 2
    minor_version: int = 0
    file_reference_number: int = 0
    parent_file_reference_number: int = 0
    usn: int = 0
    timestamp: int = 0  # raw FILETIME
    reason: int = 0
    source_info: int = 0
    security_id: int = 0
    file_attributes: int = 0
    filename: str = ""

    @property
    def timestamp_dt(self) -> Optional[datetime.datetime]:
        return filetime_to_datetime(self.timestamp)

    @property
    def frn_entry(self) -> int:
        """48-bit MFT entry index."""
        return self.file_reference_number & 0x0000FFFFFFFFFFFF

    @property
    def frn_sequence(self) -> int:
        """16-bit sequence number."""
        return (self.file_reference_number >> 48) & 0xFFFF

    def has_flag(self, flag: int) -> bool:
        return bool(self.reason & flag)


@dataclass
class EventChain:
    """Reconstructed event chain for a single file (FRN)."""
    frn: int
    filename: str = ""
    events: List[USNRecord] = field(default_factory=list)
    has_create: bool = False
    has_data_extend: bool = False
    has_basic_info_change: bool = False
    has_close: bool = False
    delta_t_finalize: Optional[float] = None  # seconds
    classification: str = "UNKNOWN"  # BENIGN_EXTRACTION | CONFIRMED_TIMESTOMP | UNKNOWN


@dataclass
class FilterResult:
    """Tier 2 output for a single file."""
    frn: int
    filename: str
    classification: str
    delta_t_finalize: Optional[float]
    has_basic_info_change: bool
    event_count: int
    details: List[str] = field(default_factory=list)


# ── USN Journal binary parser ───────────────────────────────────────

USN_RECORD_V2_MIN_SIZE = 60


def parse_usn_records(filepath: str) -> List[USNRecord]:
    """Parse raw $UsnJrnl:$J file into USN records."""
    records = []
    with open(filepath, "rb") as f:
        data = f.read()

    pos = 0
    data_len = len(data)

    while pos < data_len - USN_RECORD_V2_MIN_SIZE:
        # Skip zero-filled pages
        if data[pos:pos + 8] == b"\x00" * 8:
            # Align to next 8-byte boundary
            pos += 8
            continue

        try:
            record_length = struct.unpack_from("<I", data, pos)[0]
            if record_length < USN_RECORD_V2_MIN_SIZE or pos + record_length > data_len:
                pos += 8
                continue

            major_ver = struct.unpack_from("<H", data, pos + 4)[0]
            minor_ver = struct.unpack_from("<H", data, pos + 6)[0]

            if major_ver != 2:
                pos += 8
                continue

            frn = struct.unpack_from("<Q", data, pos + 8)[0]
            parent_frn = struct.unpack_from("<Q", data, pos + 16)[0]
            usn = struct.unpack_from("<Q", data, pos + 24)[0]
            timestamp = struct.unpack_from("<Q", data, pos + 32)[0]
            reason = struct.unpack_from("<I", data, pos + 40)[0]
            source_info = struct.unpack_from("<I", data, pos + 44)[0]
            security_id = struct.unpack_from("<I", data, pos + 48)[0]
            file_attrs = struct.unpack_from("<I", data, pos + 52)[0]
            name_length = struct.unpack_from("<H", data, pos + 56)[0]
            name_offset = struct.unpack_from("<H", data, pos + 58)[0]

            name_start = pos + name_offset
            filename = ""
            if name_start + name_length <= data_len:
                filename = data[name_start:name_start + name_length].decode("utf-16-le", errors="replace")

            rec = USNRecord(
                record_length=record_length,
                major_version=major_ver,
                minor_version=minor_ver,
                file_reference_number=frn,
                parent_file_reference_number=parent_frn,
                usn=usn,
                timestamp=timestamp,
                reason=reason,
                source_info=source_info,
                security_id=security_id,
                file_attributes=file_attrs,
                filename=filename,
            )
            records.append(rec)
            pos += record_length
            # Align to 8-byte boundary
            if pos % 8 != 0:
                pos += 8 - (pos % 8)

        except struct.error:
            pos += 8
            continue

    return records


# ── Event Chain Reconstruction ───────────────────────────────────────

def build_event_chains(records: List[USNRecord]) -> Dict[int, EventChain]:
    """Group USN records by FRN and reconstruct event chains."""
    chains: Dict[int, EventChain] = {}

    for rec in records:
        frn = rec.frn_entry
        if frn not in chains:
            chains[frn] = EventChain(frn=frn, filename=rec.filename)

        chain = chains[frn]
        chain.events.append(rec)

        if rec.has_flag(USN_REASON_FILE_CREATE):
            chain.has_create = True
        if rec.has_flag(USN_REASON_DATA_EXTEND):
            chain.has_data_extend = True
        if rec.has_flag(USN_REASON_BASIC_INFO_CHANGE):
            chain.has_basic_info_change = True
        if rec.has_flag(USN_REASON_CLOSE):
            chain.has_close = True

    return chains


def _calc_delta_t(chain: EventChain) -> Optional[float]:
    """Calculate Δt_finalize between last DATA_EXTEND and BASIC_INFO_CHANGE."""
    last_data_extend_ts = None
    basic_info_change_ts = None

    for ev in chain.events:
        if ev.has_flag(USN_REASON_DATA_EXTEND):
            last_data_extend_ts = ev.timestamp
        if ev.has_flag(USN_REASON_BASIC_INFO_CHANGE):
            basic_info_change_ts = ev.timestamp

    if last_data_extend_ts and basic_info_change_ts:
        # Convert 100-nanosecond ticks to seconds
        delta = (basic_info_change_ts - last_data_extend_ts) / 10_000_000
        return abs(delta)
    return None


def classify_chain(chain: EventChain, threshold: float = DEFAULT_THRESHOLD_SECONDS) -> EventChain:
    """Classify an event chain as benign extraction or confirmed timestomping."""
    chain.delta_t_finalize = _calc_delta_t(chain)

    # Archive extraction pattern: CREATE → DATA_EXTEND → BASIC_INFO_CHANGE → CLOSE
    # with Δt_finalize ≤ threshold
    has_extraction_pattern = (
        chain.has_create and
        chain.has_data_extend and
        chain.has_basic_info_change and
        chain.has_close
    )

    if has_extraction_pattern and chain.delta_t_finalize is not None:
        if chain.delta_t_finalize <= threshold:
            chain.classification = "BENIGN_EXTRACTION"
        else:
            chain.classification = "CONFIRMED_TIMESTOMP"
    elif chain.has_basic_info_change and not chain.has_create:
        # BASIC_INFO_CHANGE on pre-existing file (no CREATE) → suspicious
        chain.classification = "CONFIRMED_TIMESTOMP"
    else:
        chain.classification = "UNKNOWN"

    return chain


# ── Tier 2: Main Filter Entry Point ─────────────────────────────────

def filter_usnjrnl(filepath: str, flagged_frns: Optional[set] = None,
                   threshold: float = DEFAULT_THRESHOLD_SECONDS) -> List[FilterResult]:
    """
    Tier 2: Parse $UsnJrnl:$J and classify flagged FRNs.
    
    Args:
        filepath: Path to raw $UsnJrnl:$J file.
        flagged_frns: Set of FRNs flagged by Tier 1. If None, analyze all.
        threshold: Δt threshold in seconds for benign classification.
    
    Returns:
        List of FilterResult with classification per file.
    """
    records = parse_usn_records(filepath)
    chains = build_event_chains(records)

    results = []
    for frn, chain in chains.items():
        if flagged_frns and frn not in flagged_frns:
            continue

        chain = classify_chain(chain, threshold)

        details = []
        if chain.has_create:
            details.append("FILE_CREATE detected")
        if chain.has_data_extend:
            details.append("DATA_EXTEND detected")
        if chain.has_basic_info_change:
            details.append("BASIC_INFO_CHANGE detected (R_USN_1)")
        if chain.has_close:
            details.append("CLOSE detected")
        if chain.delta_t_finalize is not None:
            details.append(f"Δt_finalize = {chain.delta_t_finalize:.4f}s (threshold: {threshold}s)")

        results.append(FilterResult(
            frn=frn,
            filename=chain.filename,
            classification=chain.classification,
            delta_t_finalize=chain.delta_t_finalize,
            has_basic_info_change=chain.has_basic_info_change,
            event_count=len(chain.events),
            details=details,
        ))

    return results
