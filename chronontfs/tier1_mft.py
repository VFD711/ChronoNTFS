"""
Tier 1: $MFT Attribute Divergence & Signature Screening.

Parses raw $MFT records, extracts SIA (0x10) and FNA (0x30) timestamps,
and evaluates baseline detection rules R_MFT_1 through R_MFT_3.
"""

import struct
import datetime
from dataclasses import dataclass, field
from typing import List, Optional

# NTFS epoch: 1601-01-01 00:00:00 UTC
NTFS_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
FILETIME_TICKS_PER_SECOND = 10_000_000

# Known system binary timestamp signatures for MACE cloning detection
KNOWN_CLONE_TARGETS = {
    "kernel32.dll", "ntdll.dll", "ntoskrnl.exe",
    "user32.dll", "advapi32.dll", "kernelbase.dll",
}


def filetime_to_datetime(ft: int) -> Optional[datetime.datetime]:
    """Convert 64-bit FILETIME ticks to datetime."""
    if ft == 0:
        return None
    try:
        return NTFS_EPOCH + datetime.timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def filetime_fractional_seconds(ft: int) -> int:
    """Return the sub-second 100-nanosecond ticks (fractional part)."""
    return ft % FILETIME_TICKS_PER_SECOND


@dataclass
class MACETimestamps:
    """Four MACE timestamps as raw 64-bit FILETIME values."""
    modified: int = 0
    accessed: int = 0
    created: int = 0
    entry_modified: int = 0

    @property
    def modified_dt(self):
        return filetime_to_datetime(self.modified)

    @property
    def accessed_dt(self):
        return filetime_to_datetime(self.accessed)

    @property
    def created_dt(self):
        return filetime_to_datetime(self.created)

    @property
    def entry_modified_dt(self):
        return filetime_to_datetime(self.entry_modified)


@dataclass
class MFTRecord:
    """Parsed MFT record with SIA and FNA timestamps."""
    record_number: int = 0
    sequence_number: int = 0
    filename: str = ""
    parent_ref: int = 0
    sia: MACETimestamps = field(default_factory=MACETimestamps)
    fna: MACETimestamps = field(default_factory=MACETimestamps)
    in_use: bool = False


@dataclass
class DetectionResult:
    """Result of baseline rule evaluation for a single file."""
    record_number: int
    filename: str
    r_mft_1: bool = False  # SIA_Created < FNA_Created
    r_mft_2: bool = False  # SIA_Modified < SIA_Created
    r_mft_3: bool = False  # Fractional seconds == 0
    is_clone_suspect: bool = False  # MACE cloning from known binary
    flagged: bool = False
    details: List[str] = field(default_factory=list)


# ── Raw $MFT binary parser ──────────────────────────────────────────

MFT_RECORD_SIZE = 1024
MFT_SIGNATURE = b"FILE"

# Attribute type IDs
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30


def _parse_mace_from_bytes(data: bytes, offset: int) -> MACETimestamps:
    """Extract 4 FILETIME values (32 bytes) starting at offset."""
    created, modified, entry_mod, accessed = struct.unpack_from("<QQQQ", data, offset)
    return MACETimestamps(
        created=created,
        modified=modified,
        entry_modified=entry_mod,
        accessed=accessed,
    )


def parse_mft_record(data: bytes, record_index: int = 0) -> Optional[MFTRecord]:
    """Parse a single 1024-byte raw MFT record."""
    if len(data) < MFT_RECORD_SIZE:
        return None
    if data[:4] != MFT_SIGNATURE:
        return None

    # Fixup (simplified — skip full fixup for prototype)
    flags = struct.unpack_from("<H", data, 22)[0]
    in_use = bool(flags & 0x01)
    rec_num = struct.unpack_from("<I", data, 44)[0]
    if rec_num == 0:
        rec_num = record_index

    first_attr_offset = struct.unpack_from("<H", data, 20)[0]

    record = MFTRecord(record_number=rec_num, in_use=in_use)

    # Walk attributes
    offset = first_attr_offset
    while offset + 8 < MFT_RECORD_SIZE:
        attr_type = struct.unpack_from("<I", data, offset)[0]
        if attr_type == 0xFFFFFFFF:
            break
        attr_len = struct.unpack_from("<I", data, offset + 4)[0]
        if attr_len == 0 or offset + attr_len > MFT_RECORD_SIZE:
            break

        if attr_type == ATTR_STANDARD_INFORMATION:
            # SIA timestamps start at attribute content offset
            content_offset = struct.unpack_from("<H", data, offset + 20)[0]
            abs_offset = offset + content_offset
            if abs_offset + 32 <= len(data):
                record.sia = _parse_mace_from_bytes(data, abs_offset)

        elif attr_type == ATTR_FILE_NAME:
            content_offset = struct.unpack_from("<H", data, offset + 20)[0]
            abs_offset = offset + content_offset
            if abs_offset + 66 <= len(data):
                # Parent directory ref (8 bytes)
                record.parent_ref = struct.unpack_from("<Q", data, abs_offset)[0] & 0x0000FFFFFFFFFFFF
                # FNA timestamps at offset +8 from content
                record.fna = _parse_mace_from_bytes(data, abs_offset + 8)
                # Filename
                name_len = struct.unpack_from("<B", data, abs_offset + 64)[0]
                name_ns = struct.unpack_from("<B", data, abs_offset + 65)[0]
                name_start = abs_offset + 66
                if name_start + name_len * 2 <= len(data):
                    record.filename = data[name_start:name_start + name_len * 2].decode("utf-16-le", errors="replace")

        offset += attr_len

    return record


def parse_mft_file(filepath: str) -> List[MFTRecord]:
    """Parse all records from a raw $MFT file."""
    records = []
    with open(filepath, "rb") as f:
        index = 0
        while True:
            chunk = f.read(MFT_RECORD_SIZE)
            if len(chunk) < MFT_RECORD_SIZE:
                break
            rec = parse_mft_record(chunk, index)
            if rec and rec.in_use and rec.filename:
                records.append(rec)
            index += 1
    return records


# ── Tier 1: Detection Rules ─────────────────────────────────────────

def evaluate_rules(record: MFTRecord, known_timestamps: Optional[dict] = None) -> DetectionResult:
    """Evaluate R_MFT_1, R_MFT_2, R_MFT_3 and clone detection."""
    result = DetectionResult(
        record_number=record.record_number,
        filename=record.filename,
    )

    # R_MFT_1: SIA_Created < FNA_Created (backdating)
    if record.sia.created > 0 and record.fna.created > 0:
        if record.sia.created < record.fna.created:
            result.r_mft_1 = True
            result.details.append(
                f"R_MFT_1: SIA_Created ({record.sia.created_dt}) < "
                f"FNA_Created ({record.fna.created_dt})"
            )

    # R_MFT_2: SIA_Modified < SIA_Created (internal MACE anomaly)
    if record.sia.modified > 0 and record.sia.created > 0:
        if record.sia.modified < record.sia.created:
            result.r_mft_2 = True
            result.details.append(
                f"R_MFT_2: SIA_Modified ({record.sia.modified_dt}) < "
                f"SIA_Created ({record.sia.created_dt})"
            )

    # R_MFT_3: Sub-second zeroing
    if record.sia.created > 0:
        frac_created = filetime_fractional_seconds(record.sia.created)
        frac_modified = filetime_fractional_seconds(record.sia.modified)
        if frac_created == 0 and frac_modified == 0:
            result.r_mft_3 = True
            result.details.append("R_MFT_3: SIA fractional seconds are all zeros (.0000000)")

    # Clone detection: check if SIA timestamps match known system binaries
    if known_timestamps:
        for binary_name, ts in known_timestamps.items():
            if (record.sia.created == ts.get("created", -1) and
                record.sia.modified == ts.get("modified", -1)):
                result.is_clone_suspect = True
                result.details.append(
                    f"CLONE: SIA timestamps match {binary_name}"
                )
                break

    result.flagged = result.r_mft_1 or result.r_mft_2 or result.r_mft_3 or result.is_clone_suspect
    return result


def screen_mft(filepath: str, known_timestamps: Optional[dict] = None) -> List[DetectionResult]:
    """Tier 1: Screen all MFT records and return flagged results."""
    records = parse_mft_file(filepath)
    results = []
    for rec in records:
        det = evaluate_rules(rec, known_timestamps)
        if det.flagged:
            results.append(det)
    return results
