"""
generate_samples.py — Menghasilkan file artefak dummy mentah ($MFT, $UsnJrnl, $LogFile)
untuk pengujian manual ChronoNTFS.

Menghasilkan 3 skenario file:
1. normal.txt        → File normal harian (Group A1)
2. archive_file.pdf  → File hasil ekstrak ZIP (Group A2, SIA < FNA, delta_t = 0.2s)
3. malware_stomp.exe → File korban timestomping hacker (Group B, SIA < FNA, delta_t = 4500s)
"""

import struct
import os

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(SAMPLE_DIR, exist_ok=True)

MFT_PATH = os.path.join(SAMPLE_DIR, "sample_MFT")
USN_PATH = os.path.join(SAMPLE_DIR, "sample_UsnJrnl")
LOG_PATH = os.path.join(SAMPLE_DIR, "sample_LogFile")

# Stempel Waktu (FILETIME ticks)
# 2026-11-19 (Sekarang): ~134395000000000000
# 2020-01-01 (Masa Lalu): ~132222624000000000
TS_NOW = 134_395_000_000_000_000
TS_OLD = 132_222_624_000_000_000


def build_mft_record(rec_num: int, filename: str, sia_created: int, sia_modified: int,
                     fna_created: int, fna_modified: int) -> bytes:
    """Membuat 1 record MFT biner 1024-byte mentah."""
    rec = bytearray(1024)
    # Header 'FILE'
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 20, 56)  # first_attr_offset = 56
    struct.pack_into("<H", rec, 22, 1)   # in_use = 1
    struct.pack_into("<I", rec, 44, rec_num)  # record_number = rec_num

    # Atribut 0x10 ($STANDARD_INFORMATION)
    # offset 56, panjang 72 byte, content_offset = 24
    struct.pack_into("<II", rec, 56, 0x10, 72)
    struct.pack_into("<H", rec, 56 + 20, 24)
    # MACE SIA di offset 56 + 24 = 80
    struct.pack_into("<QQQQ", rec, 80, sia_created, sia_modified, sia_modified, sia_created)

    # Atribut 0x30 ($FILE_NAME)
    # offset 128
    name_bytes = filename.encode("utf-16-le")
    name_len = len(filename)
    attr_fna_len = 66 + len(name_bytes)
    # align 8 byte
    if attr_fna_len % 8 != 0:
        attr_fna_len += 8 - (attr_fna_len % 8)

    struct.pack_into("<II", rec, 128, 0x30, attr_fna_len)
    struct.pack_into("<H", rec, 128 + 20, 24)  # content_offset = 24
    
    # FNA content di offset 128 + 24 = 152
    # offset 152: parent_ref (8 byte)
    struct.pack_into("<Q", rec, 152, 5)  # parent dir index 5
    # offset 152 + 8 = 160: MACE FNA
    struct.pack_into("<QQQQ", rec, 160, fna_created, fna_modified, fna_modified, fna_created)
    # offset 152 + 64 = 216: name length in characters (B)
    struct.pack_into("<B", rec, 216, name_len)
    # offset 152 + 66 = 218: nama file
    rec[218:218 + len(name_bytes)] = name_bytes

    # End marker 0xFFFFFFFF
    struct.pack_into("<I", rec, 128 + attr_fna_len, 0xFFFFFFFF)
    return bytes(rec)


def build_usn_record(frn: int, filename: str, reason: int, timestamp: int) -> bytes:
    """Membuat 1 record USN_RECORD_V2 biner mentah."""
    name_bytes = filename.encode("utf-16-le")
    name_len = len(name_bytes)
    rec_len = 60 + name_len
    # Align 8 byte
    if rec_len % 8 != 0:
        rec_len += 8 - (rec_len % 8)

    buf = bytearray(rec_len)
    struct.pack_into("<IHH", buf, 0, rec_len, 2, 0)
    struct.pack_into("<QQ", buf, 8, frn, 5)  # FRN, parent FRN
    struct.pack_into("<QQ", buf, 24, 100, timestamp)  # USN, timestamp
    struct.pack_into("<I", buf, 40, reason)
    struct.pack_into("<HH", buf, 56, name_len, 60)
    buf[60:60 + name_len] = name_bytes
    return bytes(buf)


def build_logfile_record(sia_undo_created: int, sia_undo_modified: int,
                         sia_redo_created: int, sia_redo_modified: int) -> bytes:
    """Membuat 1 halaman log 4096-byte dengan Undo/Redo Record."""
    page = bytearray(4096)
    page[0:4] = b"RCRD"

    # Isi log record di offset 64
    scan_pos = 64
    # redo_op = 0x07, undo_op = 0x07 (UpdateResidentValue)
    struct.pack_into("<HH", page, scan_pos + 0, 0x07, 0x07)
    # redo_offset = 16, redo_len = 32
    struct.pack_into("<HH", page, scan_pos + 4, 16, 32)
    # undo_offset = 48, undo_len = 32
    struct.pack_into("<HH", page, scan_pos + 8, 48, 32)

    # Redo MACE (hasil dipalsukan) di scan_pos + 16 = 80
    struct.pack_into("<QQQQ", page, 80, sia_redo_created, sia_redo_modified, sia_redo_modified, sia_redo_created)
    # Undo MACE (asli sebelum diubah) di scan_pos + 48 = 112
    struct.pack_into("<QQQQ", page, 112, sia_undo_created, sia_undo_modified, sia_undo_modified, sia_undo_created)

    return bytes(page)


def main():
    print("Menghasilkan sampel artefak dummy...")

    # 1. Bangun $MFT
    with open(MFT_PATH, "wb") as f:
        # File 1: normal.txt (SIA >= FNA, fractional ticks ada)
        f.write(build_mft_record(101, "normal.txt", TS_NOW + 500, TS_NOW + 1000, TS_NOW, TS_NOW))
        # File 2: archive_file.pdf (SIA < FNA, anomali khas ZIP)
        f.write(build_mft_record(102, "archive_file.pdf", TS_OLD + 123, TS_OLD + 456, TS_NOW, TS_NOW))
        # File 3: malware_stomp.exe (SIA < FNA, anomali hacker)
        f.write(build_mft_record(103, "malware_stomp.exe", TS_OLD + 789, TS_OLD + 999, TS_NOW, TS_NOW))

    # 2. Bangun $UsnJrnl
    with open(USN_PATH, "wb") as f:
        # File 2 (archive_file.pdf) -> Ekstraksi cepat (Δt = 0.2 detik = 2_000_000 ticks)
        f.write(build_usn_record(102, "archive_file.pdf", 0x00000100, TS_NOW))             # FILE_CREATE
        f.write(build_usn_record(102, "archive_file.pdf", 0x00000002, TS_NOW + 1_000_000))   # DATA_EXTEND
        f.write(build_usn_record(102, "archive_file.pdf", 0x00008000, TS_NOW + 3_000_000))   # BASIC_INFO_CHANGE (Δt = 0.2s)
        f.write(build_usn_record(102, "archive_file.pdf", 0x80000000, TS_NOW + 4_000_000))   # CLOSE

        # File 3 (malware_stomp.exe) -> Timestomping manual (tidak ada CREATE beruntun / jeda lama)
        f.write(build_usn_record(103, "malware_stomp.exe", 0x00000100, TS_NOW))
        f.write(build_usn_record(103, "malware_stomp.exe", 0x00000002, TS_NOW + 1_000_000))
        # Hacker mengubah stempel waktu 4500 detik kemudian (Δt = 4500 detik)
        f.write(build_usn_record(103, "malware_stomp.exe", 0x00008000, TS_NOW + 45_000_000_000))
        f.write(build_usn_record(103, "malware_stomp.exe", 0x80000000, TS_NOW + 45_001_000_000))

    # 3. Bangun $LogFile
    with open(LOG_PATH, "wb") as f:
        # Simpan jejak undo/redo untuk file 103 (malware_stomp.exe)
        # Undo = TS_NOW (asli), Redo = TS_OLD (palsu)
        f.write(build_logfile_record(TS_NOW, TS_NOW, TS_OLD + 789, TS_OLD + 999))

    print(f"✓ Berhasil dibuat di folder {SAMPLE_DIR}:")
    print(f"  - {MFT_PATH}")
    print(f"  - {USN_PATH}")
    print(f"  - {LOG_PATH}")


if __name__ == "__main__":
    main()
