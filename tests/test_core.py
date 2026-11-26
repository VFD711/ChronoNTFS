"""
Self-check: Basic assert tests for ChronoNTFS core logic.
Run: python -m pytest tests/ or python tests/test_core.py
"""

import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chronontfs.tier1_mft import (
    filetime_to_datetime,
    filetime_fractional_seconds,
    MACETimestamps,
    MFTRecord,
    evaluate_rules,
)
from chronontfs.tier2_usnjrnl import (
    EventChain,
    USNRecord,
    USN_REASON_FILE_CREATE,
    USN_REASON_DATA_EXTEND,
    USN_REASON_BASIC_INFO_CHANGE,
    USN_REASON_CLOSE,
    classify_chain,
)
from chronontfs.tier3_logfile import calculate_delta_t


def test_filetime_conversion():
    """Test FILETIME to datetime conversion."""
    # 2024-01-01 00:00:00 UTC in FILETIME ticks
    ft = 133_485_408_000_000_000
    dt = filetime_to_datetime(ft)
    assert dt is not None
    assert dt.year == 2024
    assert dt.month == 1
    assert dt.day == 1
    print("✓ filetime_to_datetime OK")


def test_fractional_seconds_zero():
    """R_MFT_3: Detect sub-second zeroing."""
    # Timestamp with no fractional part (exact second)
    ft_whole = 133_476_288_000_000_000  # .0000000
    assert filetime_fractional_seconds(ft_whole) == 0
    print("✓ R_MFT_3 zero detection OK")


def test_fractional_seconds_nonzero():
    """Normal file should have non-zero fractional seconds."""
    ft_normal = 133_476_288_008_492_011  # .8492011
    assert filetime_fractional_seconds(ft_normal) != 0
    print("✓ R_MFT_3 normal fractional OK")


def test_r_mft_1_backdating():
    """R_MFT_1: SIA_Created < FNA_Created → backdating detected."""
    rec = MFTRecord(
        record_number=100,
        filename="malware.exe",
        in_use=True,
        sia=MACETimestamps(
            created=130_000_000_000_000_000,   # 2012 (old/forged)
            modified=130_000_000_000_000_000,
        ),
        fna=MACETimestamps(
            created=133_476_288_000_000_000,   # 2024 (real)
            modified=133_476_288_000_000_000,
        ),
    )
    result = evaluate_rules(rec)
    assert result.r_mft_1 is True, "R_MFT_1 should fire"
    assert result.flagged is True
    print("✓ R_MFT_1 backdating detection OK")


def test_r_mft_1_normal():
    """Normal file: SIA_Created >= FNA_Created → no flag."""
    rec = MFTRecord(
        record_number=101,
        filename="document.txt",
        in_use=True,
        sia=MACETimestamps(
            created=133_476_288_008_492_011,   # normal fractional
            modified=133_476_300_003_271_544,   # normal fractional
        ),
        fna=MACETimestamps(
            created=133_476_288_008_492_011,
            modified=133_476_288_008_492_011,
        ),
    )
    result = evaluate_rules(rec)
    assert result.r_mft_1 is False
    assert result.flagged is False
    print("✓ R_MFT_1 normal file OK")


def test_r_mft_2_mace_anomaly():
    """R_MFT_2: SIA_Modified < SIA_Created → internal MACE error."""
    rec = MFTRecord(
        record_number=102,
        filename="suspicious.dll",
        in_use=True,
        sia=MACETimestamps(
            created=133_476_288_000_000_000,   # 2024
            modified=130_000_000_000_000_000,  # 2012 (impossible)
        ),
        fna=MACETimestamps(
            created=133_476_288_000_000_000,
            modified=133_476_288_000_000_000,
        ),
    )
    result = evaluate_rules(rec)
    assert result.r_mft_2 is True, "R_MFT_2 should fire"
    print("✓ R_MFT_2 MACE anomaly detection OK")


def test_r_mft_3_subsecond_zeroing():
    """R_MFT_3: Both created and modified have zero fractional seconds."""
    rec = MFTRecord(
        record_number=103,
        filename="stamped.exe",
        in_use=True,
        sia=MACETimestamps(
            created=133_476_288_000_000_000,   # .0000000
            modified=133_476_300_000_000_000,  # .0000000
        ),
        fna=MACETimestamps(
            created=133_476_288_000_000_000,
            modified=133_476_288_000_000_000,
        ),
    )
    result = evaluate_rules(rec)
    assert result.r_mft_3 is True, "R_MFT_3 should fire"
    print("✓ R_MFT_3 sub-second zeroing OK")


def test_tier2_benign_extraction():
    """Tier 2: Archive extraction pattern with Δt ≤ 1.0s → BENIGN."""
    base_ts = 133_476_288_000_000_000
    chain = EventChain(
        frn=200,
        filename="extracted.pdf",
        events=[
            USNRecord(timestamp=base_ts, reason=USN_REASON_FILE_CREATE),
            USNRecord(timestamp=base_ts + 5_000_000, reason=USN_REASON_DATA_EXTEND),  # +0.5s
            USNRecord(timestamp=base_ts + 7_000_000, reason=USN_REASON_BASIC_INFO_CHANGE),  # +0.7s
            USNRecord(timestamp=base_ts + 8_000_000, reason=USN_REASON_CLOSE),  # +0.8s
        ],
        has_create=True,
        has_data_extend=True,
        has_basic_info_change=True,
        has_close=True,
    )
    result = classify_chain(chain, threshold=1.0)
    assert result.classification == "BENIGN_EXTRACTION"
    assert result.delta_t_finalize is not None
    assert result.delta_t_finalize <= 1.0
    print("✓ Tier 2 benign extraction classification OK")


def test_tier2_confirmed_timestomp():
    """Tier 2: BASIC_INFO_CHANGE on existing file without CREATE → CONFIRMED."""
    base_ts = 133_476_288_000_000_000
    chain = EventChain(
        frn=201,
        filename="malware.exe",
        events=[
            USNRecord(timestamp=base_ts + 50_000_000_000, reason=USN_REASON_BASIC_INFO_CHANGE),  # +5000s later
        ],
        has_create=False,
        has_data_extend=False,
        has_basic_info_change=True,
        has_close=False,
    )
    result = classify_chain(chain, threshold=1.0)
    assert result.classification == "CONFIRMED_TIMESTOMP"
    print("✓ Tier 2 confirmed timestomping classification OK")


def test_tier3_delta_t_calculation():
    """Tier 3: |ΔT| calculation between recovered and ground truth."""
    recovered = 133_476_288_010_000_000  # +1ms offset
    ground_truth = 133_476_288_000_000_000
    delta = calculate_delta_t(recovered, ground_truth)
    assert delta == 1000.0  # 1000 ms = 1 second
    print("✓ Tier 3 |ΔT| calculation OK")


if __name__ == "__main__":
    test_filetime_conversion()
    test_fractional_seconds_zero()
    test_fractional_seconds_nonzero()
    test_r_mft_1_backdating()
    test_r_mft_1_normal()
    test_r_mft_2_mace_anomaly()
    test_r_mft_3_subsecond_zeroing()
    test_tier2_benign_extraction()
    test_tier2_confirmed_timestomp()
    test_tier3_delta_t_calculation()

    print("\n══════════════════════════════════")
    print("  All ChronoNTFS self-checks PASSED ✓")
    print("══════════════════════════════════")
