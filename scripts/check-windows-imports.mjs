#!/usr/bin/env node
// Fail if a shipped Windows .exe imports the MSVC C runtime from a DLL.
//
// This is the guard behind `.cargo/config.toml`'s `+crt-static`. The flag is one line and its
// absence is invisible: a dynamically-linked gateway runs perfectly on every machine that has ever
// had Visual Studio or a VC++ redistributable on it (every dev box, every CI runner image) and
// exits 0xC0000135 before `main` on a clean Windows install, printing nothing. Nothing about the
// build says which one you produced. The import table does.
//
// It reads the PE import directory (and the delay-load directory, which is a second way in) and
// rejects the CRT DLL families by name. Everything else is listed and allowed: an allowlist of
// system DLLs would fail the day a dependency touches a new Win32 API, which trains people to
// weaken the check.
//
// Usage: node scripts/check-windows-imports.mjs <file.exe> [<file.exe> ...]

import fs from "node:fs";

// Two distinct families, both fatal, for different reasons.
//
// REDIST is the one that kills the process: those DLLs ship in the Visual C++ redistributable, which
// a clean Windows install does not have, so the loader fails before `main` with 0xC0000135.
//
// UCRT is an operating-system component and IS present on a clean Windows 10/11, so importing it does
// not break anything by itself. It is rejected anyway because under `+crt-static` it cannot appear:
// seeing it means the flag is gone, which means the REDIST import is back too or one bump away.
const REDIST = /^(vcruntime\d|msvcp\d|msvcr\d|concrt\d)/i;
const UCRT = /^(ucrtbase|api-ms-win-crt-)/i;

function u16(buf, off) { return buf.readUInt16LE(off); }
function u32(buf, off) { return buf.readUInt32LE(off); }

/** Section table, used to turn an RVA into a file offset. */
function sections(buf, peOff, sizeOfOptionalHeader, numberOfSections) {
  const base = peOff + 24 + sizeOfOptionalHeader;
  const out = [];
  for (let i = 0; i < numberOfSections; i++) {
    const s = base + i * 40;
    out.push({
      name: buf.toString("latin1", s, s + 8).replace(/\0+$/, ""),
      virtualSize: u32(buf, s + 8),
      virtualAddress: u32(buf, s + 12),
      sizeOfRawData: u32(buf, s + 16),
      pointerToRawData: u32(buf, s + 20),
    });
  }
  return out;
}

function rvaToOffset(secs, rva) {
  for (const s of secs) {
    // VirtualSize can be smaller than SizeOfRawData (and vice versa); accept the larger span so a
    // name sitting in the file-aligned tail still resolves.
    const span = Math.max(s.virtualSize, s.sizeOfRawData);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
      return s.pointerToRawData + (rva - s.virtualAddress);
    }
  }
  return null;
}

function cstring(buf, off) {
  if (off === null || off < 0 || off >= buf.length) return null;
  const end = buf.indexOf(0, off);
  return buf.toString("latin1", off, end === -1 ? buf.length : end);
}

function parseImports(file) {
  const buf = fs.readFileSync(file);
  if (buf.length < 0x40 || buf.toString("latin1", 0, 2) !== "MZ") {
    throw new Error(`${file}: not a PE image (no MZ header)`);
  }
  const peOff = u32(buf, 0x3c);
  if (buf.toString("latin1", peOff, peOff + 4) !== "PE\0\0") {
    throw new Error(`${file}: not a PE image (no PE signature at 0x${peOff.toString(16)})`);
  }
  const numberOfSections = u16(buf, peOff + 6);
  const sizeOfOptionalHeader = u16(buf, peOff + 20);
  const optOff = peOff + 24;
  const magic = u16(buf, optOff);
  // PE32 puts the data directories 96 bytes into the optional header; PE32+ (which every 64-bit
  // Windows target is) puts them at 112 because five header fields widen to 8 bytes.
  const ddOff = optOff + (magic === 0x20b ? 112 : 96);
  const numberOfRvaAndSizes = u32(buf, ddOff - 4);
  const secs = sections(buf, peOff, sizeOfOptionalHeader, numberOfSections);
  const names = new Set();

  const dir = (index) => {
    if (index >= numberOfRvaAndSizes) return { rva: 0, size: 0 };
    return { rva: u32(buf, ddOff + index * 8), size: u32(buf, ddOff + index * 8 + 4) };
  };

  // Directory 1: the ordinary import table. 20-byte IMAGE_IMPORT_DESCRIPTORs, terminated by a
  // zeroed entry; the DLL name is an RVA at +12.
  const imports = dir(1);
  if (imports.rva) {
    let off = rvaToOffset(secs, imports.rva);
    if (off === null) throw new Error(`${file}: import directory RVA 0x${imports.rva.toString(16)} is in no section`);
    for (;;) {
      const nameRva = u32(buf, off + 12);
      const originalFirstThunk = u32(buf, off);
      const firstThunk = u32(buf, off + 16);
      if (nameRva === 0 && originalFirstThunk === 0 && firstThunk === 0) break;
      const name = cstring(buf, rvaToOffset(secs, nameRva));
      if (name) names.add(name);
      off += 20;
    }
  }

  // Directory 13: delay-load imports. A second, quieter way to depend on a DLL: the loader does not
  // resolve it at start-up, so the process reaches `main` and dies later on the first call instead.
  // 32-byte descriptors; bit 0 of Attributes says whether the fields are RVAs (they are, in anything
  // this millennium) or absolute VAs.
  const delay = dir(13);
  if (delay.rva) {
    let off = rvaToOffset(secs, delay.rva);
    if (off !== null) {
      for (;;) {
        const attributes = u32(buf, off);
        const nameField = u32(buf, off + 4);
        if (attributes === 0 && nameField === 0) break;
        const rva = (attributes & 1) ? nameField : nameField - u32(buf, optOff + (magic === 0x20b ? 24 : 28));
        const name = cstring(buf, rvaToOffset(secs, rva));
        if (name) names.add(name);
        off += 32;
      }
    }
  }

  return [...names].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
}

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("usage: node scripts/check-windows-imports.mjs <file.exe> [...]");
  process.exit(2);
}

const FIX =
  "Restore `-C target-feature=+crt-static` for the *-pc-windows-msvc targets (.cargo/config.toml), " +
  "and check nothing in the environment is overriding RUSTFLAGS: an env RUSTFLAGS replaces that file " +
  "wholesale rather than merging with it.";

let failed = false;
for (const file of files) {
  const names = parseImports(file);
  const redist = names.filter((n) => REDIST.test(n));
  const ucrt = names.filter((n) => UCRT.test(n));
  console.log(`${file}\n  imports: ${names.join(", ") || "(none)"}`);
  if (redist.length) {
    failed = true;
    console.error(
      `::error file=${file}::${file} imports the Visual C++ redistributable (${redist.join(", ")}). ` +
        "A clean Windows install does not have those DLLs, so this binary exits 0xC0000135 " +
        `(STATUS_DLL_NOT_FOUND) before main on a user's machine, printing nothing. ${FIX}`,
    );
  } else if (ucrt.length) {
    failed = true;
    console.error(
      `::error file=${file}::${file} links the UCRT dynamically (${ucrt.join(", ")}). Those DLLs are ` +
        "part of Windows so this binary still starts, but they cannot appear in a +crt-static build: " +
        `the static CRT has been dropped and the redistributable import is one dependency bump away. ${FIX}`,
    );
  } else {
    console.log("  OK: the C runtime is linked statically");
  }
}
process.exit(failed ? 1 : 0);
