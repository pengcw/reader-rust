#!/usr/bin/env python3
"""Prepare a private, patched Cargo dependency; never modify Cargo's registry."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

VERSION = "0.12.2"
ARCHIVE_SHA256 = "a13ac243b86a74120814ef7e9e30ad5a2c1199b7b9963b1cf7c84e4cdc1cad99"
SOURCE_SHA256 = "ce9a95d3c011f255c1facb7d4361c71209e71ba58d84acd3281a755d0686a285"
PATCHED_FILES = ("quickjs/quickjs.c", "quickjs/quickjs-opcode.h", "src/lib.rs")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root, cargo_home):
    package = f"rquickjs-sys-{VERSION}"
    patch = root / "patches/quickjs-string-length.patch"
    locked = (root / "Cargo.lock").read_text()
    sys_package, = [p for p in locked.split("[[package]]")
                   if '\nname = "rquickjs-sys"\n' in p]
    if (f'\nversion = "{VERSION}"\n' not in sys_package
            or f'\nchecksum = "{ARCHIVE_SHA256}"\n' not in sys_package):
        raise RuntimeError("rquickjs-sys lock changed; review/rebase the QuickJS patch first")
    identity = digest(patch)
    destination = root / "target/patched-quickjs" / package
    stamp = destination / ".legado-patch"
    if stamp.exists() and all((destination / name).exists() for name in PATCHED_FILES):
        expected = identity + "\n" + "".join(digest(destination / name) + "\n"
                                             for name in PATCHED_FILES)
        if stamp.read_text() == expected:
            print(f"QuickJS length patch ready: {destination}")
            return destination
    archives = sorted((cargo_home / "registry/cache").glob(f"*/{package}.crate"))
    archives = [p for p in archives if digest(p) == ARCHIVE_SHA256]
    if not archives:
        raise RuntimeError(
            f"Missing verified {package}.crate in Cargo cache. "
            "Run cargo fetch --locked --target <your-target> first "
            "(add --offline when dependencies are cached)."
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="prepare-", dir=destination.parent) as temp:
        with tarfile.open(archives[0], "r:gz") as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if (not parts or parts[0] != package or ".." in parts
                        or not (member.isfile() or member.isdir())):
                    raise RuntimeError("Unexpected member in verified crate archive")
            archive.extractall(temp)
        staged = Path(temp) / package
        if digest(staged / "quickjs/quickjs.c") != SOURCE_SHA256:
            raise RuntimeError("Unexpected QuickJS source; refusing to apply patch")
        subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)],
            cwd=staged, check=True,
        )
        (staged / ".legado-patch").write_text(
            identity + "\n" + "".join(digest(staged / name) + "\n" for name in PATCHED_FILES)
        )
        if destination.exists():
            shutil.rmtree(destination)
        shutil.move(str(staged), destination)
    print(f"QuickJS length patch ready: {destination}")
    return destination


def prepare_core(root, cargo_home):
    package = "rquickjs-core-0.12.2"
    checksum = "16e4f499ac5b943d97ee6dbc44f23c2c10426f420f7d2f1793d6318911b6608c"
    locked = (root / "Cargo.lock").read_text()
    entry, = [p for p in locked.split("[[package]]")
              if '\nname = "rquickjs-core"\n' in p]
    if '\nversion = "0.12.2"\n' not in entry or checksum not in entry:
        raise RuntimeError("rquickjs-core lock changed; review the string wrapper patch")
    patch = root / "patches/rquickjs-string-wrapper.patch"
    destination = root / "target/patched-quickjs" / package
    source = destination / "src/value/convert/from.rs"
    stamp = destination / ".legado-patch"
    identity = digest(patch)
    if source.exists() and (destination / "src/lib.rs").exists() and stamp.exists() and stamp.read_text() == identity + "\n" + digest(source) + "\n" + digest(destination / "src/lib.rs"):
        return destination
    archives = [p for p in (cargo_home / "registry/cache").glob(f"*/{package}.crate")
                if digest(p) == checksum]
    if not archives:
        raise RuntimeError(f"Missing verified {package}.crate; run cargo fetch --locked")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="prepare-core-", dir=destination.parent) as temp:
        with tarfile.open(archives[0], "r:gz") as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != package or ".." in parts or not (member.isfile() or member.isdir()):
                    raise RuntimeError("Unexpected member in rquickjs-core archive")
            archive.extractall(temp)
        staged = Path(temp) / package
        subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)],
                       cwd=staged, check=True)
        (staged / ".legado-patch").write_text(identity + "\n" + digest(staged / "src/value/convert/from.rs") + "\n" + digest(staged / "src/lib.rs"))
        if destination.exists():
            shutil.rmtree(destination)
        shutil.move(str(staged), destination)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-home", type=Path,
                        default=Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    cargo_home = args.cargo_home.expanduser().resolve()
    prepare(root, cargo_home)
    prepare_core(root, cargo_home)


if __name__ == "__main__":
    main()
