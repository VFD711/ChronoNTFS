"""
Tier 3: $LogFile Transactional Carving & Timestamp Recovery.

Parses NTFS $LogFile (ARIES-based transaction log), locates
UpdateResidentValue (0x07) operations targeting attribute 0x10 (SIA),
and extracts original pre-tampered timestamps from Undo records.
"""

import struct
import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict

NTFS_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# $LogFile page signatures
RSTR_SIGNATURE = b"RSTR"
RCRD_SIGNATURE = b"RCRD"

# Operation codes
OP_UPDATE_RESIDENT_VALUE = 0x07

# Target attribute for SIA
ATTR_STANDARD_INFORMATION = 0x10

LOG_PAGE_SIZE = 4096


def filetime_to_datetime(ft: int) -> Optional[datetime.datetime]:
    if ft == 0:
        return None
    try:
        return NTFS_EPOCH + datetime.timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


@dataclass
class LogRecord:
    """Parsed $LogFile log record."""
    lsn: int = 0
    client_previous_lsn: int = 0
    redo_op: int = 0
    undo_op: int = 0
    target_attribute: int = 0
    mft_cluster_index: int = 0
    target_vcn: int = 0
    redo_offset: int = 0
    redo_length: int = 0
    undo_offset: int = 0
    undo_length: int = 0
    redo_data: bytes = b""
    undo_data: bytes = b""


@dataclass
class RecoveredTimestamp:
    """Original timestamp recovered from $LogFile Undo record."""
    mft_record_hint: int = 0
    lsn: int = 0
    # Pre-tampered (original) timestamps from Undo
    original_created: Optional[int] = None
    original_modified: Optional[int] = None
    original_accessed: Optional[int] = None
    original_entry_modified: Optional[int] = None
    # Forged timestamps from Redo
    forged_created: Optional[int] = None
    forged_modified: Optional[int] = None

    @property
    def original_created_dt(self):
        return filetime_to_datetime(self.original_created) if self.original_created else None

    @property
    def original_modified_dt(self):
        return filetime_to_datetime(self.original_modified) if self.original_modified else None

    @property
    def forged_created_dt(self):
        return filetime_to_datetime(self.forged_created) if self.forged_created else None

    @property
    def forged_modified_dt(self):
        return filetime_to_datetime(self.forged_modified) if self.forged_modified else None


@dataclass
class RecoveryResult:
    """Tier 3 output for a single file."""
    frn: int
    filename: str
    recovery_method: str  # PRIMARY_LOGFILE | FALLBACK_FNA | FAILED
    recovered: Optional[RecoveredTimestamp] = None
    fallback_fna_created: Optional[int] = None
    delta_t_ms: Optional[float] = None  # |ΔT| in milliseconds
    details: List[str] = field(default_factory=list)


# ── $LogFile binary parser ──────────────────────────────────────────

def _extract_timestamps_from_sia_bytes(data: bytes) -> Dict[str, int]:
    """Extract MACE timestamps from SIA attribute bytes (first 32 bytes)."""
    if len(data) < 32:
        return {}
    created, modified, entry_mod, accessed = struct.unpack_from("<QQQQ", data, 0)
    return {
        "created": created,
        "modified": modified,
        "entry_modified": entry_mod,
        "accessed": accessed,
    }


def parse_logfile(filepath: str) -> List[LogRecord]:
    """
    Parse $LogFile and extract log records with Undo/Redo data.
    
    ponytail: Simplified parser scanning for UpdateResidentValue ops
    targeting SIA. Full ARIES restart-area walk needed for production.
    """
    records = []

    with open(filepath, "rb") as f:
        data = f.read()

    data_len = len(data)
    pos = 0

    while pos <= data_len - LOG_PAGE_SIZE:
        page_sig = data[pos:pos + 4]

        if page_sig == RCRD_SIGNATURE:
            # Scan within RCRD page for log record entries
            page_data = data[pos:pos + LOG_PAGE_SIZE]
            _scan_rcrd_page(page_data, pos, records)

        pos += LOG_PAGE_SIZE

    return records


def _scan_rcrd_page(page_data: bytes, page_offset: int, records: List[LogRecord]):
    """Scan an RCRD page for log record entries targeting SIA updates."""
    page_len = len(page_data)
    # Skip page header (typically 64 bytes for RCRD)
    scan_pos = 64

    while scan_pos < page_len - 40:
        try:
            # Look for potential log record header pattern
            # This is a simplified heuristic scan
            redo_op = struct.unpack_from("<H", page_data, scan_pos + 0)[0]
            undo_op = struct.unpack_from("<H", page_data, scan_pos + 2)[0]

            # Check if this is an UpdateResidentValue targeting SIA
            if redo_op == OP_UPDATE_RESIDENT_VALUE or undo_op == OP_UPDATE_RESIDENT_VALUE:
                redo_offset = struct.unpack_from("<H", page_data, scan_pos + 4)[0]
                redo_length = struct.unpack_from("<H", page_data, scan_pos + 6)[0]
                undo_offset = struct.unpack_from("<H", page_data, scan_pos + 8)[0]
                undo_length = struct.unpack_from("<H", page_data, scan_pos + 10)[0]

                # Validate lengths (SIA timestamps = 32 bytes minimum)
                if 32 <= redo_length <= 72 and 32 <= undo_length <= 72:
                    redo_data = b""
                    undo_data = b""

                    redo_abs = scan_pos + redo_offset
                    undo_abs = scan_pos + undo_offset

                    if redo_abs + redo_length <= page_len:
                        redo_data = page_data[redo_abs:redo_abs + redo_length]
                    if undo_abs + undo_length <= page_len:
                        undo_data = page_data[undo_abs:undo_abs + undo_length]

                    if redo_data and undo_data:
                        rec = LogRecord(
                            redo_op=redo_op,
                            undo_op=undo_op,
                            redo_offset=redo_offset,
                            redo_length=redo_length,
                            undo_offset=undo_offset,
                            undo_length=undo_length,
                            redo_data=redo_data,
                            undo_data=undo_data,
                        )
                        records.append(rec)

            scan_pos += 8  # Advance by 8-byte alignment

        except struct.error:
            scan_pos += 8
            continue


# ── Tier 3: Recovery Engine ──────────────────────────────────────────

def recover_timestamps(logfile_path: str,
                       confirmed_frns: Optional[set] = None,
                       fna_fallback: Optional[Dict[int, int]] = None,
                       ground_truth: Optional[Dict[int, int]] = None) -> List[RecoveryResult]:
    """
    Tier 3: Attempt to recover original timestamps from $LogFile.

    Args:
        logfile_path: Path to raw $LogFile.
        confirmed_frns: FRNs confirmed as timestomped by Tier 2.
        fna_fallback: Dict of FRN → FNA_Created timestamp (fallback).
        ground_truth: Dict of FRN → ground truth timestamp for ΔT calc.

    Returns:
        List of RecoveryResult per file.
    """
    log_records = parse_logfile(logfile_path)
    results = []

    # Extract potential timestamp recoveries from log records
    recoveries: List[RecoveredTimestamp] = []
    for rec in log_records:
        if len(rec.undo_data) >= 32 and len(rec.redo_data) >= 32:
            undo_ts = _extract_timestamps_from_sia_bytes(rec.undo_data)
            redo_ts = _extract_timestamps_from_sia_bytes(rec.redo_data)

            # Only keep if undo and redo differ (actual timestamp change)
            if undo_ts.get("created") != redo_ts.get("created"):
                recovery = RecoveredTimestamp(
                    lsn=rec.lsn,
                    original_created=undo_ts.get("created"),
                    original_modified=undo_ts.get("modified"),
                    original_accessed=undo_ts.get("accessed"),
                    original_entry_modified=undo_ts.get("entry_modified"),
                    forged_created=redo_ts.get("created"),
                    forged_modified=redo_ts.get("modified"),
                )
                recoveries.append(recovery)

    return recoveries


def calculate_delta_t(recovered_ts: int, ground_truth_ts: int) -> float:
    """Calculate |ΔT| in milliseconds between recovered and ground truth."""
    delta_ticks = abs(recovered_ts - ground_truth_ts)
    return delta_ticks / 10_000  # Convert 100ns ticks to milliseconds
