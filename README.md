# mikebom-cmake-demo

A minimal C project (cmake + ninja) that demonstrates how
[mikebom](https://github.com/kusari-sandbox/mikebom) analyzes C/C++
projects from BOTH ends of the build pipeline:

1. **Source-tree scan** — reads `CMakeLists.txt`, identifies declared
   third-party dependencies (this demo: zlib pulled via
   `FetchContent_Declare`), and emits a source-tier SBOM.
2. **Binary scan** — analyzes the compiled `crc-demo` executable for
   dynamic-linkage signals + statically-embedded library
   identification via mikebom's external symbol-fingerprint corpus
   (the [`kusari-sandbox/mikebom-fingerprints`](https://github.com/kusari-sandbox/mikebom-fingerprints)
   sibling repo).
3. **Cross-tier alignment** (alpha.45+) — when both scans run
   together against the project root, the binary-tier fingerprint
   match is automatically attributed to the source-tier PURL the
   cmake reader emitted. ONE component per real library across the
   whole SBOM, regardless of how many tiers identified it.

The three combined answer three complementary questions:

- "What does this project **say** it depends on?" → source scan.
- "What does this binary **actually contain**?" → binary scan.
- "Do the two stories agree?" → cross-tier alignment.

## Project shape

```text
.
├── CMakeLists.txt   # FetchContent_Declare(zlib v1.3.1) + static link
├── src/main.c       # exercises 10 zlib API entry points
└── README.md
```

The cmake project pins zlib to `v1.3.1` via `FetchContent_Declare`,
builds it as a static library, and links it into `crc-demo`. The
program drives `crc32` + `adler32` + `compress` + `uncompress` + a
manual `deflate`/`inflate` stream pipeline so all 10 of mikebom's
zlib fingerprint symbols end up referenced from `main()`.

`ENABLE_EXPORTS TRUE` on the executable adds `-rdynamic` on Linux
(no-op on macOS / Windows). This surfaces zlib's statically-embedded
symbols in the binary's dynamic-symbol table so the fingerprint
matcher can identify them. Real-world parallel: any binary that
loads plugins via `dlopen()` does this — those binaries are exactly
the class the fingerprint matcher targets.

## Prerequisites

- `cmake >= 3.16`
- `ninja-build`
- A C compiler (`gcc` or `clang`)
- `git` (for `FetchContent_Declare` to clone zlib)
- `mikebom` — build from source or grab a release binary

## Step 1 — Build

```bash
cmake -S . -B build -G Ninja
ninja -C build
./build/crc-demo
```

Expected output:

```text
zlib version:  1.3.1
crc32:         0x33e9f5d2
adler32:       0x01be0d90
compress():    36 -> 44 bytes
uncompress():  36 bytes match input
deflate stream: 44 bytes out
inflate stream: 36 bytes back
```

## Step 2 — Source-tree scan

Scan the source tree (with the build directory temporarily moved out
of the way, so the source-tree readers run alone without the binary
scanner muddying the output):

```bash
mv build /tmp/cmake-demo-build
mikebom sbom scan --path . --output source.cdx.json --no-deep-hash
mv /tmp/cmake-demo-build build
```

Inspect the emitted components:

```bash
jq '.components[] | {purl, name, type}' source.cdx.json
```

```json
{
  "purl": "pkg:github/madler/zlib@v1.3.1",
  "name": "zlib",
  "type": "library"
}
```

The cmake reader parsed `FetchContent_Declare(zlib GIT_REPOSITORY
... GIT_TAG v1.3.1)` and emitted a `pkg:github/madler/zlib@v1.3.1`
component. Note the version is pinned to the cmake declaration —
no network access needed to identify the dep. The PURL is the
canonical github PURL form so vulnerability scanners can resolve
it against advisory databases.

## Step 3 — Binary scan (macOS or Linux)

```bash
mikebom sbom scan --path build/ --output binary.cdx.json --no-deep-hash
jq '.components[] | {purl, name, type, evidence: ([.properties[]? | select(.name == "mikebom:evidence-kind") | .value][0])}' binary.cdx.json
```

macOS sample output (your hashes will differ):

```json
{
  "purl": "pkg:generic/%2Fusr%2Flib%2FlibSystem.B.dylib",
  "name": "/usr/lib/libSystem.B.dylib",
  "type": "library",
  "evidence": "dynamic-linkage"
}
{
  "purl": "pkg:generic/crc-demo?file-sha256=...",
  "name": "crc-demo",
  "type": "application",
  "evidence": null
}
{
  "purl": "pkg:generic/libz.1.dylib?file-sha256=...",
  "name": "libz.1.dylib",
  "type": "library",
  "evidence": null
}
```

Notice:

- `crc-demo` is emitted as the file-level binary component, keyed on
  its SHA-256.
- The static `libz.a` is captured as a library artifact alongside
  the binary (cmake's static-build pipeline also produces the .dylib
  variants — those show up too).
- `libSystem.B.dylib` is the macOS C runtime, detected via
  dynamic-linkage analysis of the Mach-O `LC_LOAD_DYLIB` entries.

## Step 4 — Binary scan with the external fingerprint corpus

The symbol-fingerprint matcher works natively across all three major
binary formats — ELF (Linux), Mach-O (macOS, alpha.44), and PE
(Windows, alpha.45+). Each format reaches a different table to find
the exported symbols (`.dynsym` for ELF, `LC_SYMTAB` externals for
Mach-O, `IMAGE_EXPORT_DIRECTORY` for PE), but the corpus content +
matching threshold are identical across platforms.

On Windows, the canonical fingerprint-matcher target is a DLL that
re-exports a statically-embedded library's API (a wrapper DLL around
zlib, openssl, etc.). Stripped Windows EXEs that use a library
internally without re-exporting it have an empty export table — same
shape limitation as the ELF/Mach-O scanners.

Scan the build directory with the external corpus opt-in:

```bash
SCAN_DIR=$(mktemp -d)
cp build/crc-demo "$SCAN_DIR/"
mikebom sbom scan \
    --path "$SCAN_DIR" \
    --output binary-fp.cdx.json \
    --no-deep-hash \
    --fingerprints-corpus
```

Inspect the fingerprint match:

```bash
jq '.components[] | select((.properties // [])[] | (.name == "mikebom:fingerprint-corpus-sha")) | {purl, name, corpus_sha: ([.properties[] | select(.name == "mikebom:fingerprint-corpus-sha") | .value][0]), symbols_matched: ([.properties[] | select(.name == "mikebom:fingerprint-symbols-matched") | .value][0])}' binary-fp.cdx.json
```

```json
{
  "purl": "pkg:generic/zlib",
  "name": "zlib",
  "corpus_sha": "fff39c6ad22c",
  "symbols_matched": "10/10"
}
```

What this is saying:

- The matcher found a `pkg:generic/zlib` component in the
  `crc-demo` binary based on its exported-symbol fingerprint
  (10 of 10 zlib API symbols present in the dynamic-symbol table).
- The fingerprint that produced the match came from corpus revision
  `fff39c6ad22c` of `kusari-sandbox/mikebom-fingerprints`.
- A consumer can resolve that 12-hex prefix back to the exact
  fingerprint record per the
  [docs/reference/identifiers.md §11 recipe](https://github.com/kusari-sandbox/mikebom/blob/main/docs/reference/identifiers.md#section-11--milestone-108-external-corpus-provenance-mikebomfingerprint-corpus-sha):
  ```bash
  curl -fsSL https://api.github.com/repos/kusari-sandbox/mikebom-fingerprints/commits/fff39c6ad22c \
      | jq -r '.sha'
  # → fff39c6ad22ce8420b506323ce1d5cce4b628d5c
  curl -fsSL https://github.com/kusari-sandbox/mikebom-fingerprints/archive/fff39c6ad22ce8420b506323ce1d5cce4b628d5c.tar.gz | tar xz -C /tmp
  jq '.' /tmp/mikebom-fingerprints-fff39c6ad22ce8420b506323ce1d5cce4b628d5c/corpus/zlib.json
  ```

### macOS-specific implementation note

mikebom's Mach-O extraction reads `LC_SYMTAB`'s external symbols
(`N_EXT` flag set) and strips the leading `_` that the Mach-O C ABI
prepends to every C symbol. The bundled C example here exports
zlib's API because `set_target_properties(crc-demo PROPERTIES
ENABLE_EXPORTS TRUE)` in `CMakeLists.txt` adds `-rdynamic` on Linux
+ enables the equivalent export-symbol behavior on macOS — real-
world parallel: any binary that loads plugins via `dlopen()` does
this, and those are the binaries the fingerprint matcher is most
useful for.

## Step 5 — Cross-tier alignment: source + binary SBOMs equality-join (alpha.45+)

Pre-milestone-109, the project-root scan emitted TWO zlib components
under different PURLs — the source-tier `pkg:github/madler/zlib@v1.3.1`
from the cmake reader AND the binary-tier `pkg:generic/zlib` from
the symbol-fingerprint matcher. Consumers diffing source + binary
SBOMs saw a phantom mismatch.

As of mikebom `v0.1.0-alpha.45+`, scanning the project root with
`--fingerprints-corpus` produces ONE zlib component carrying BOTH
sources' evidence on a single source-tier PURL:

```bash
$ mikebom sbom scan --path . --output sbom.cdx.json --no-deep-hash --fingerprints-corpus
$ jq '[.components[] | select(.name == "zlib")] | length' sbom.cdx.json
1
$ jq '.components[] | select(.name == "zlib") | {purl, properties: [.properties[] | {name, value}]}' sbom.cdx.json
{
  "purl": "pkg:github/madler/zlib@v1.3.1",
  "properties": [
    { "name": "mikebom:source-mechanism",            "value": "cmake-fetchcontent-git" },
    { "name": "mikebom:fingerprint-corpus-sha",      "value": "fff39c6ad22c" },
    { "name": "mikebom:fingerprint-symbols-matched", "value": "10/10" },
    { "name": "mikebom:sbom-tier",                   "value": "source" }
  ]
}
```

The mechanism: when mikebom scans a cmake project root, it walks
the build tree for `_deps/<name>-build/` directories (cmake's
documented `FetchContent_Declare` output layout). When a fingerprint
match's library name resolves against a cmake declaration that
produced one of those build dirs, the binary-tier match's PURL is
rewritten to the source-tier value. The downstream dedup pipeline
then merges the two components by shared PURL into one final
component carrying both sources' evidence.

This means consumers can equality-join source-only and binary-tier
SBOMs by PURL with no consumer-side fixup:

```bash
# CI pipeline: emit source-only SBOM at PR-merge time
$ mikebom sbom scan --path src/ --output source.cdx.json --no-deep-hash

# Release-build pipeline: emit binary SBOM at release time
$ mikebom sbom scan --path . --output binary.cdx.json --no-deep-hash --fingerprints-corpus

# Triage at vuln-scan time: which deps were declared but not linked?
$ comm -23 \
    <(jq -r '.components[].purl' source.cdx.json | sort) \
    <(jq -r '.components[].purl' binary.cdx.json | sort)
# (empty when everything declared was also linked; otherwise the
# legitimate "declared but not linked" signal — pkg:github/curl/curl@... etc.)
```

See [milestone 109 spec](https://github.com/kusari-sandbox/mikebom/tree/main/specs/109-binary-source-purl-binding)
for the full design + scope (cmake `FetchContent_Declare` only this
milestone; `ExternalProject_Add` / Bazel / Meson tracked as
follow-ons).

## What this demo does NOT cover

- **Cross-tier binding via `--bind-to-source`**: the milestone-072
  `--bind-to-source` flag is a SEPARATE mechanism for binding image-
  tier SBOMs (typically deb/rpm/apk) to source-tier SBOMs via
  per-component binding fingerprints. This demo's milestone-109
  source+binary alignment (Step 5 above) is a different mechanism
  scoped to single-scan-tree cmake projects. A follow-on extension
  could add `mikebom trace run` build-tier capture for full
  cross-document binding.
- **Air-gapped pre-fetch**: `mikebom fingerprints fetch` + tar +
  ship + offline scan is covered by the
  [milestone-108 quickstart](https://github.com/kusari-sandbox/mikebom/blob/main/specs/108-fingerprint-corpus/quickstart.md#scenario-2--air-gapped-operator-pre-fetches-the-corpus).
- **vcpkg / Conan / CPM.cmake** dep declarations: the cmake reader
  supports all three (milestone 102-103). This demo uses
  `FetchContent` because it requires no external package-manager
  setup; the lookup recipes for the others are analogous. The
  milestone-109 cross-tier attribution only applies to
  `FetchContent_Declare` this release; vcpkg / Conan binding ships
  in a follow-on milestone.

## Reproducing on a clean checkout

```bash
git clone https://github.com/kusari-sandbox/mikebom-cmake-demo.git
cd mikebom-cmake-demo

# Step 1
cmake -S . -B build -G Ninja && ninja -C build

# Step 2
mv build /tmp/cmake-demo-build
mikebom sbom scan --path . --output source.cdx.json --no-deep-hash
mv /tmp/cmake-demo-build build

# Step 3
mikebom sbom scan --path build/ --output binary.cdx.json --no-deep-hash

# Step 4 (works natively on macOS + Linux + Windows as of mikebom v0.1.0-alpha.45)
SCAN_DIR=$(mktemp -d) && cp build/crc-demo "$SCAN_DIR/"
mikebom sbom scan --path "$SCAN_DIR" --output binary-fp.cdx.json --no-deep-hash --fingerprints-corpus

# Step 5 (cross-tier alignment: source + binary emit ONE component per real library)
mikebom sbom scan --path . --output sbom.cdx.json --no-deep-hash --fingerprints-corpus
jq '.components[] | select(.name == "zlib") | .purl' sbom.cdx.json
# → "pkg:github/madler/zlib@v1.3.1" (ONE component, both sources' evidence merged)
```

## License

Apache-2.0.
