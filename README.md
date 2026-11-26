# ChronoNTFS

**Reducing False Positives in NTFS Timestomping Detection through USN Journal Sequence Analysis and $LogFile Timestamp Recovery on Windows 11.**

## Overview

ChronoNTFS is a three-tier forensic analysis CLI tool that detects NTFS timestamp manipulation (timestomping) while suppressing false positives caused by archive extraction (ZIP/7z/RAR).

### Three-Tier Pipeline

| Tier | Name | Artifact | Purpose |
|------|------|----------|---------|
| 1 | **Screen** | `$MFT` | Detect SIA/FNA divergence, sub-second zeroing, MACE cloning |
| 2 | **Filter** | `$UsnJrnl:$J` | Suppress ZIP extraction false positives via event sequence timing |
| 3 | **Recover** | `$LogFile` | Recover original pre-tampered timestamps from undo records |

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Full three-tier analysis
python -m chronontfs analyze --mft MFT_FILE --usnjrnl USNJRNL_FILE --logfile LOGFILE_FILE

# Tier 1 only (MFT screening)
python -m chronontfs screen --mft MFT_FILE

# Tier 2 filter (USN Journal)
python -m chronontfs filter --usnjrnl USNJRNL_FILE

# Tier 3 recovery ($LogFile)
python -m chronontfs recover --logfile LOGFILE_FILE --mft MFT_FILE
```

## Detection Rules (Baseline)

- **R_MFT_1**: `SIA_Created < FNA_Created` → Backdating anomaly
- **R_MFT_2**: `SIA_Modified < SIA_Created` → Internal MACE sequence error
- **R_MFT_3**: `SIA fractional seconds == .0000000` → Legacy tool signature
- **R_USN_1**: `BASIC_INFO_CHANGE` flag in USN Journal → Metadata change indicator

## References

- Palmbach & Breitinger (2020) — Baseline heuristic rules
- Oh, Lee & Hwang (2022) — $LogFile transactional carving
- Dreier et al. (2024) — Implicit timing and event sequencing

## License

MIT
