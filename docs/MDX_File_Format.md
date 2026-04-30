# MDict File Format Specification

This document describes the binary format of MDict `.mdx` dictionary files, reverse-engineered from the [MDict](https://www.mdict.cn/) application.

All multi-byte integers are stored in **big-endian** byte order unless otherwise noted.

## Overview

There are three format versions:

| Version | `RequiredEngineVersion` | Integer width | Key section position | Content section position |
|---------|------------------------|---------------|---------------------|------------------------|
| V1 | 1.0 | 4-byte (uint32) | Before content | After key section |
| V2 | 2.0 | 8-byte (uint64) | Before content | After key section |
| V3 | 3.0 | Mixed | After content | Before key section |

## File Layout

### V1/V2

```
+------------------------------------------+
| Meta Section                             |
|   length(4B) | header_xml | adler32(4B)  |
+------------------------------------------+
| Key Section                              |
|   section_info | [checksum] | index | blocks |
+------------------------------------------+
| Content Section                          |
|   section_info | index | blocks            |
+------------------------------------------+
```

### V3

```
+------------------------------------------+
| Meta Section                             |
|   length(4B) | header_xml | adler32(4B)  |
+------------------------------------------+
| Content Section (unit_info pairs)        |
|   CONTENT unit + CONTENT_BLOCK_INDEX unit|
+------------------------------------------+
| Key Section (unit_info pairs)            |
|   KEY unit + KEY_BLOCK_INDEX unit        |
+------------------------------------------+
```

---

## Meta Section

```
+----------+--------------------+----------+
| length   | header_str         | checksum |
| 4B BE    | (length bytes)     | 4B LE    |
+----------+--------------------+----------+
```

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| +0 | 4 | `length` | Big-endian uint32, byte length of `header_str` |
| +4 | `length` | `header_str` | XML metadata, typically UTF-16LE encoded |
| +4+length | 4 | `checksum` | Little-endian uint32, Adler32 of `header_str` bytes |

### Encoding Detection

If the first two bytes of `header_str` are `0x3C 0x00`, the data is UTF-16LE encoded. Otherwise it is treated as UTF-8.

### Version Detection

The `RequiredEngineVersion` XML attribute determines the format version:
- `"1.0"` → V1
- `"2.0"` → V2
- `"3.0"` → V3

If absent, V1 is assumed. If `Encoding` is absent, V3 defaults to UTF-8; V1/V2 default to UTF-16.

### XML Attributes

| Attribute | Field | Type | Description |
|-----------|-------|------|-------------|
| `RequiredEngineVersion` | version | float | Format version (1.0, 2.0, 3.0) |
| `Encrypted` | encrypted | uint8 | Encryption bitmask: 0=none, 1=info, 2=data, 3=both |
| `Encoding` | encoding | string | Character encoding: "UTF-8", "UTF-16", "Big5", "GBK", "GB2312", "GB18030" |
| `Format` | format | string | Content format: "Html" or "Text" |
| `Title` | title | string | Dictionary title |
| `Description` | description | string | Dictionary description |
| `StyleSheet` | style_sheet | string | CSS stylesheet |
| `Compact` | compact | bool | Compact format flag |
| `Compat` | compat | bool | Compatibility flag |
| `KeyCaseSensitive` | key_case_sensitive | bool | Case-sensitive key matching |
| `StripKey` | strip_key | bool | Strip key whitespace |
| `Left2Right` | left2right | bool | Reading direction |
| `UUID` | uuid | string | Unique identifier (V3) |
| `RegCode` | reg_code | string | Registration code |
| `RegisterBy` | register_by | string | Registration method |
| `CreationDate` | creation_date | string | Creation timestamp |
| `DefaultSortingLocale` | default_sorting_locale | string | Sorting locale for ICU |

### Encryption

The `Encrypted` attribute is a bitmask:

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 1 | Key block index info_para is encrypted (Salsa20) |
| 1 | 2 | Key block index data is encrypted (simple XOR) |
| both | 3 | Both info_para and data are encrypted |

#### Key Derivation

**With registration code:**

1. `derivation_key = RIPEMD128(device_id_bytes)`
2. `real_key = Salsa20Decrypt(hex_decode(reg_code), derivation_key)` — 128-bit output

The registration code is read from a `.key` file adjacent to the `.mdx` file, or from the `RegCode` XML attribute.

**Without registration code (V3):**

```
crypto_key = fast_hash_128(uuid_bytes)
```

**V2 storage block key (double RIPEMD-128):**

```
temp = RIPEMD128(crypto_key, crypto_key_len)
derived_key = RIPEMD128(temp, 16)
```

---

## V3 Unit Info

V3 uses self-describing blocks prefixed by a **24-byte** header:

```
+-------------+----------+----------+--------------+---------------------+
| block_type  | reserved | reserved | block_count  | data_section_length |
| 1B          | 3B       | 8B BE    | 4B BE        | 8B BE               |
+-------------+----------+----------+--------------+---------------------+
```

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| +0 | 1 | `unit_type` | Block type identifier |
| +1 | 3 | `reserved1` | Reserved bytes |
| +4 | 8 | `reserved2` | Reserved (BE uint64) |
| +12 | 4 | `block_count` | Number of sub-blocks (BE uint32) |
| +16 | 8 | `data_section_length` | Data section byte length (BE uint64) |

### Block Types

| Value | Name | Description |
|-------|------|-------------|
| 0 | INVALID | Unused |
| 1 | CONTENT | Content data block |
| 2 | CONTENT_BLOCK_INDEX | Content block index |
| 3 | KEY | Key data block |
| 4 | KEY_BLOCK_INDEX | Key block index |

---

## Key Section

### V1/V2 Layout

```
+----------------------+
| section_info       |  16B (V1) / 40B (V2)
+----------------------+
| checksum (V2 only)   |  4B
+----------------------+
| key_block_index_data |  index_comp_len bytes
+----------------------+
| key_blocks_data      |  blocks_len bytes
+----------------------+
```

### V1 section_info (16 bytes)

| Offset | Size | Field |
|--------|------|-------|
| +0 | 4 | `num_blocks` (BE uint32) |
| +4 | 4 | `num_entries` (BE uint32) |
| +8 | 4 | `index_comp_len` (BE uint32) |
| +12 | 4 | `blocks_len` (BE uint32) |

V1 index data is raw (uncompressed). No checksum field.

### V2 section_info (40 bytes)

| Offset | Size | Field |
|--------|------|-------|
| +0 | 8 | `num_blocks` (BE uint64) |
| +8 | 8 | `num_entries` (BE uint64) |
| +16 | 8 | `index_decomp_len` (BE uint64) |
| +24 | 8 | `index_comp_len` (BE uint64) |
| +32 | 8 | `blocks_len` (BE uint64) |

V2 section_info may be Salsa20-encrypted (when `Encrypted` bit 0 is set). The checksum field that follows is Adler32 of the **plaintext** section_info bytes (BE uint32).

V2 index data uses the standard storage block format (8-byte header + compressed body). The 8-byte header:
- Bytes 0–3: compression type (`0x02 0x00 0x00 0x00` = zlib)
- Bytes 4–7: Adler32 checksum

If data encryption is enabled (bit 1), the data after the 8-byte header is decrypted with simple XOR:

```
input   = [header_bytes[4..7]] [0x95] [0x36] [0x00] [0x00]   // 8 bytes total
xor_key = RIPEMD128(input)
```

### Key Block Index Entry

Each entry in the decompressed index describes one compressed key block.

**V1 format:**

| Field | Size | Description |
|-------|------|-------------|
| `entry_count` | 4B (BE uint32) | Number of keys in this block |
| `first_key` | 1B length + data | Length-prefixed key (uint8 byte count, no terminator) |
| `last_key` | 1B length + data | Length-prefixed key (uint8 byte count, no terminator) |
| `comp_size` | 4B (BE uint32) | Compressed block size |
| `decomp_size` | 4B (BE uint32) | Decompressed block size |

**V2/V3 format:**

| Field | Size | Description |
|-------|------|-------------|
| `entry_count` | 8B (BE uint64) | Number of keys in this block |
| `first_key` | 2B length + data + terminator | Length-prefixed key (uint16 BE char count + null terminator) |
| `last_key` | 2B length + data + terminator | Length-prefixed key (uint16 BE char count + null terminator) |
| `comp_size` | 8B (BE uint64) | Compressed block size |
| `decomp_size` | 8B (BE uint64) | Decompressed block size |

Key length is in **character count**; for UTF-16, multiply by 2 to get byte count. Terminator is 1 byte (`0x00`) for UTF-8, 2 bytes (`0x00 0x00`) for UTF-16. V1 keys have no terminator.

### Key Block Data

Each decompressed key block contains sequential entries:

**V1:**

| Field | Size |
|-------|------|
| `content_logical_offset` | 4B (BE uint32) |
| `key_raw` | null-terminated string (1-byte null) |

**V2/V3:**

| Field | Size |
|-------|------|
| `content_logical_offset` | 8B (BE uint64) |
| `key_raw` | null-terminated string (1-byte null for UTF-8, 2-byte null for UTF-16) |

`key_raw` is stored in the file's native encoding.

### V3 Key Section Layout

```
+--------------------------------------+
| unit_info (KEY, type=3)              |  24B
+--------------------------------------+
| key data section                     |  data_section_length bytes
+--------------------------------------+
| storage_block (data_info XML)        |  V3 storage block
|   XML attribute: keyCount            |
+--------------------------------------+
| unit_info (KEY_BLOCK_INDEX, type=4)  |  24B
+--------------------------------------+
| key index data section               |  data_section_length bytes
+--------------------------------------+
| storage_block (data_info XML)        |  V3 storage block
|   XML attribute: blockCount          |
+--------------------------------------+
| storage_block (actual index entries) |  V3 storage block
+--------------------------------------+
```

---

## Content Section

### V1/V2 Layout

```
+---------------------------+
| section_info            |  16B (V1) / 32B (V2)
+---------------------------+
| content_block_index_data  |  block_index_data_len bytes (raw, uncompressed)
+---------------------------+
| content blocks            |  remaining data
+---------------------------+
```

**V1 section_info (16 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| +0 | 4 | `block_count` (BE uint32) |
| +4 | 4 | `record_count` (BE uint32) |
| +8 | 4 | `block_index_data_len` (BE uint32) |
| +12 | 4 | `block_size` (BE uint32) |

**V2 section_info (32 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| +0 | 8 | `block_count` (BE uint64) |
| +8 | 8 | `record_count` (BE uint64) |
| +16 | 8 | `block_index_data_len` (BE uint64) |
| +24 | 8 | `block_size` (BE uint64) |

### Content Block Index Entry

**V1:**

| Field | Size |
|-------|------|
| `comp_size` | 4B (BE uint32) |
| `decomp_size` | 4B (BE uint32) |

**V2/V3:**

| Field | Size |
|-------|------|
| `comp_size` | 8B (BE uint64) |
| `decomp_size` | 8B (BE uint64) |

### V3 Content Section Layout

```
+----------------------------------------------+
| unit_info (CONTENT, type=1)                  |  24B
+----------------------------------------------+
| content data section                         |  data_section_length bytes
+----------------------------------------------+
| storage_block (data_info XML)                |  V3 storage block
|   XML attributes: encoding, recordCount      |
+----------------------------------------------+
| unit_info (CONTENT_BLOCK_INDEX, type=2)      |  24B
+----------------------------------------------+
| content index data section                   |  data_section_length bytes
+----------------------------------------------+
| storage_block (data_info XML)                |  V3 storage block
|   XML attributes: encoding, recordCount      |
+----------------------------------------------+
| storage_block (actual index entries)         |  V3 storage block
+----------------------------------------------+
```

---

## Storage Block

Each compressed data block has an 8-byte header:

```
+------+---------+----------+----------+------------------+
| type | enc_len | reserved | checksum | compressed_data  |
| 1B   | 1B      | 2B BE    | 4B BE    | (variable)       |
+------+---------+----------+----------+------------------+
```

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| +0 | 1 | `enc_comp_type` | High nibble = encryption type, low nibble = compression type |
| +1 | 1 | `encrypted_data_len` | Length of encrypted portion |
| +2 | 2 | `reserved` | Reserved (BE uint16) |
| +4 | 4 | `checksum` | Adler32 checksum (BE uint32) |
| +8 | var | `data` | Compressed/encrypted data |

### Encryption Types (high nibble)

| Value | Algorithm | Description |
|-------|-----------|-------------|
| 0x00 | None | No encryption |
| 0x01 | Simple XOR | In-place XOR decryption with derived key |
| 0x02 | Salsa20 | Salsa20 stream cipher decryption |

### Compression Types (low nibble)

| Value | Algorithm | Description |
|-------|-----------|-------------|
| 0x00 | None | Raw data |
| 0x01 | LZO | MiniLZO decompression |
| 0x02 | zlib | zlib `uncompress()` |

### Checksum Semantics

- When **encrypted** (`enc_type != 0x00`): Adler32 of compressed data (after decryption)
- When **not encrypted**: Adler32 of decompressed data

### V3 Storage Block Prefix

V3 blocks are prefixed with two additional length fields before the standard storage block:

```
+----------+----------+-------------------+
| dst_len  | src_len  | standard block... |
| 4B BE    | 4B BE    |                   |
+----------+----------+-------------------+
```

`dst_len` is the expected decompressed size; `src_len` is the compressed size (including the 8-byte storage block header).
