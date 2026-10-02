#!/usr/bin/env python3
"""Reject e-ink release binaries with the wrong ABI or newer glibc than the toolchain.

This is a static gate; real-device ffi.load and API smoke tests are still required.
"""

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

TARGETS = {
    "armv7-unknown-linux-gnueabi": (40, 32, 0x200, "ld-linux.so.3"),
    "armv7-unknown-linux-gnueabihf": (40, 32, 0x400, "ld-linux-armhf.so.3"),
    "aarch64-unknown-linux-gnu": (183, 64, None, "ld-linux-aarch64.so.1"),
}
ALLOWED_NEEDED = {
    "libc.so.6", "libm.so.6", "libgcc_s.so.1", "libpthread.so.0",
    "libdl.so.2", "librt.so.1", "libresolv.so.2", "libatomic.so.1",
}
# debug_parse is an internal operation exposed through reader_eval, not a C ABI symbol.
REQUIRED_SYMBOLS = {
    "reader_eval",
    "reader_execute",
    "reader_free_string",
    "reader_set_host_services",
}


def readelf(*args):
    return subprocess.check_output(["readelf", "-W", *args], text=True, stderr=subprocess.STDOUT)


def glibc_from_sysroot(root):
    libc = root / "lib" / "libc.so.6"
    if not libc.is_file():
        raise ValueError(f"missing target libc {libc}")
    version_info = readelf("--version-info", str(libc))
    sections = version_info.split("Version definition section", 1)
    if len(sections) != 2:
        raise ValueError(f"missing GLIBC version definitions in {libc}")
    definitions = sections[1].split("Version needs section", 1)[0]
    versions = [tuple(map(int, version)) for version in
                re.findall(r"\bName:\s*GLIBC_(\d+)\.(\d+)\b", definitions)]
    if not versions:
        raise ValueError(f"no GLIBC versions defined by {libc}")
    return max(versions)


def check(path, target, sysroot):
    machine, bits, float_abi, loader = TARGETS[target]
    data = path.read_bytes()[:64]
    if (len(data) < (64 if bits == 64 else 52) or data[:4] != b"\x7fELF"
            or data[4] != bits // 32 or data[5:7] != b"\x01\x01"):
        raise ValueError(f"expected {bits}-bit little-endian ELF")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type != 3 or e_machine != machine:
        raise ValueError(f"wrong shared-object type or CPU: {e_type}, {e_machine}")
    if bits == 32:
        flags = struct.unpack_from("<I", data, 36)[0]
        if (flags & 0xFF000000) != 0x05000000 or (flags & 0x600) != float_abi:
            raise ValueError(f"expected EABI5 {target} float ABI, ELF flags=0x{flags:08x}")

    if not (sysroot / "lib" / loader).exists():
        raise ValueError(f"missing target ELF loader {loader} in {sysroot}/lib")

    dynamic = readelf("-d", str(path))
    needed = set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic))
    if not needed or "libc.so.6" not in needed:
        raise ValueError(f"missing target libc: {sorted(needed)}")
    wrong_loaders = {name for name in needed if name.startswith("ld-linux") and name != loader}
    if wrong_loaders:
        raise ValueError(f"loader ABI mismatch: {sorted(wrong_loaders)}")
    if needed - ALLOWED_NEEDED - {loader}:
        raise ValueError(f"unexpected dependencies: {sorted(needed - ALLOWED_NEEDED - {loader})}")
    if "(TEXTREL)" in dynamic:
        raise ValueError("text relocations")

    version_info = readelf("--version-info", str(path))
    versions = {(int(major), int(minor)) for major, minor in
                re.findall(r"\bGLIBC_(\d+)\.(\d+)\b", version_info)}
    baseline = glibc_from_sysroot(sysroot)
    if any(version > baseline for version in versions):
        raise ValueError(f"needs GLIBC newer than toolchain {baseline}: {sorted(versions)}")
    if "GLIBC_PRIVATE" in version_info:
        raise ValueError("depends on private glibc symbols")

    symbols = readelf("--dyn-syms", str(path))
    undefined_globals = re.findall(r"\bGLOBAL\s+DEFAULT\s+UND\s+(\S+)", symbols)
    if target == "armv7-unknown-linux-gnueabi" and any(
        symbol.split("@", 1)[0] == "getauxval" for symbol in undefined_globals
    ):
        raise ValueError("Kindle EGLIBC 2.12 binary must not import getauxval")

    exports = set(re.findall(r"\bFUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+(\S+)", symbols))
    if missing := REQUIRED_SYMBOLS - exports:
        raise ValueError(f"missing Lua FFI symbols: {sorted(missing)}")
    print(f"{target} OK: libc baseline={baseline}, required GLIBC={max(versions, default=(0, 0))}, "
          f"needed={sorted(needed)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--sysroot", type=Path, required=True)
    args = parser.parse_args()
    try:
        check(args.library.resolve(), args.target, args.sysroot.resolve())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"e-ink compatibility check FAILED: {exc}")
