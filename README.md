# cmdx

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C](https://img.shields.io/badge/C-11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard))
[![CI](https://github.com/unidict/cmdx/actions/workflows/ci.yml/badge.svg)](https://github.com/unidict/cmdx/actions/workflows/ci.yml)

**cmdx** — A C library for reading **MDict dictionary files** (`.mdx` format).

cmdx parses compressed and encrypted MDict dictionary files. It handles multiple format versions (V1/V2/V3), block decompression (zlib, LZO), encryption (Salsa20, RIPEMD-128), and ICU-based locale-aware keyword sorting.

## Features

- **Multi-version Support** — Parses MDict V1, V2, and V3 format files
- **Keyword Lookup** — Exact and prefix matching with binary search across key block indexes
- **Metadata Parsing** — Extracts title, description, encoding, and other attributes from the XML header
- **On-demand Decompression** — Block-level decompression (zlib, LZO) with LRU cache (16 slots)
- **Encryption** — Supports Salsa20 stream cipher with RIPEMD-128 key derivation
- **ICU Collation** — Locale-aware keyword comparison for V3 dictionaries
- **Cross-platform** — Linux, macOS, Windows

## Building

### Prerequisites

- C compiler with C11 support
- CMake 3.14+
- zlib
- ICU (libicuuc, libicui18n)
- libiconv

### Install Dependencies

**macOS:**
```bash
xcode-select --install
brew install icu4c
```

**Ubuntu/Debian:**
```bash
sudo apt-get install zlib1g-dev libicu-dev
```

### Build from Source

```bash
git clone https://github.com/unidict/cmdx.git
cd cmdx

mkdir build && cd build
cmake ..
cmake --build .

# Run tests
ctest --output-on-failure
```

#### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMDX_BUILD_TESTS` | `ON` | Build unit tests |
| `BUILD_SHARED_LIBS` | `OFF` | Build shared library instead of static |

## Platform Support

| Platform | Status       |
|----------|--------------|
| macOS    | Tested       |
| Linux    | Tested (CI)  |
| Windows  | Tested (CI)  |

## Quick Start

### Open a Dictionary

```c
#include "cmdx_reader.h"

int main() {
    cmdx_reader *reader = cmdx_reader_open("dictionary.mdx", NULL);
    if (!reader) {
        fprintf(stderr, "Failed to open dictionary\n");
        return 1;
    }

    // Use reader...

    cmdx_reader_close(reader);
    return 0;
}
```

### Look Up Keywords

```c
// Exact match — get content records for "hello"
cvector(cmdx_data *) records =
    cmdx_get_content_records_by_key(reader, "hello", 1, false);
for (size_t i = 0; i < cvector_size(records); i++) {
    printf("%.*s\n", (int)records[i]->length, records[i]->data);
}
cvector_free(records);

// Prefix match — find all entries starting with "hel"
cvector(cmdx_key_index *) indexes =
    cmdx_get_key_indexes_by_key(reader, "hel", 10, true);
for (size_t i = 0; i < cvector_size(indexes); i++) {
    printf("%s\n", indexes[i]->key);
}
cvector_free(indexes);
```

## Architecture

```
                     cmdx_reader (top-level API)
                    /            |            \
              cmdx_meta    cmdx_key_section  cmdx_content_section
           (XML header)  (keyword index)    (definitions)
                |              |                    |
          crypto/         cmdx_storage_block    cmdx_storage_block
       (salsa20,         (zlib/LZO + LRU)     (zlib/LZO + LRU)
        ripemd128)
```

- **cmdx_reader** — Opens the file, parses metadata, builds key and content sections
- **cmdx_meta** — Parses the MDict XML header (encoding, format, encryption flags)
- **cmdx_key_section** — Binary-searchable keyword index with V1/V2/V3 parsing
- **cmdx_content_section** — Content block index and on-demand block decompression
- **cmdx_storage_block** — Storage block decoder: 8-byte header, decryption, decompression
- **crypto/** — Salsa20 stream cipher, RIPEMD-128 hash, simple XOR decryption

## Thread Safety

cmdx is **not thread-safe**. For concurrent access, create a separate reader per thread.

## License

```
MIT License

Copyright (c) 2026 kejinlu <kejinlu@gmail.com> (cmdx project)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Acknowledgments

cmdx incorporates the following third-party components:

- **[zlib](https://zlib.net/)** by Jean-loup Gailly and Mark Adler (zlib License)
- **[ICU](https://icu.unicode.org/)** by Unicode Consortium (ICU License)
- **[libiconv](https://www.gnu.org/software/libiconv/)** by GNU Project (LGPL License)
- **[minilzo](https://www.oberhumer.com/opensource/lzo/)** by Markus F.X.J. Oberhumer (GPL License)
- **[Unity Test Framework](https://github.com/ThrowTheSwitch/Unity)** by ThrowTheSwitch (MIT License)
- **[cvector](https://github.com/eteran/cvector/)** by Evan Teran (MIT License)

## See Also

- [MDX File Format Specification](docs/MDX_File_Format.md)
