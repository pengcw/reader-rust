#!/usr/bin/env python3
"""XPath ABI safety regression. Build first, then run with --library PATH.

Each case loads the real cdylib in a fresh, disposable process. A crash,
incorrect value, or timeout fails the parent. No third-party packages needed.
"""
import argparse
import ctypes
import json
from pathlib import Path
import subprocess
import sys

XML = '<?xml version="1.0"?><root note="urn:x:books"><branch xmlns:x="urn:books"><x:Item x:id="a">Book</x:Item></branch></root>'
CASES = [
    ("declared-prefix", XML, "//x:Item", ["Book"]),
    ("declared-attribute", XML, "//x:Item[@x:id='a']", ["Book"]),
    ("unknown-prefix", XML, "//unknown:Item", []),
    ("unknown-attribute", XML, "//root[@unknown:id]", []),
    ("unknown-wildcard", XML, "//unknown:*", []),
    ("quoted-colons", XML, "//root[@note='urn:x:books']/branch/x:Item", ["Book"]),
    ("axis-not-prefix", XML, "//branch/child::x:Item", ["Book"]),
    ("invalid-expression", XML, "//x:Item[", []),
    ("valid-no-match", XML, "//x:Missing", []),
    ("js-declared-prefix", XML, '@js:java.getString("//x:Item")', "Book"),
    ("js-unknown-prefix", XML, '@js:java.getString("//unknown:Item")', ""),
    ("js-node-context-roundtrip", XML,
     '@js:const item=java.getElement("//x:Item",result); [item.attr("x:id"),item.select("@xpath:parent::branch").size(),java.getString("@xpath:.",item)].join("|")',
     "a|1|Book"),
    ("js-node-context-unknown-prefix", XML,
     '@js:java.getElement("//x:Item",result).select(".//unknown:Missing").size()', "0"),
]


def child(library, index):
    # Do not leave core dumps behind when testing regressions on Unix.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except ImportError:
        pass
    name, body, rule, expected = CASES[index]
    lib = ctypes.CDLL(str(library))
    lib.reader_eval.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.reader_eval.restype = ctypes.c_void_p
    lib.reader_free_string.argtypes = [ctypes.c_void_p]
    lib.reader_free_string.restype = None
    pointer = lib.reader_eval(body.encode(), rule.encode())
    if not pointer:
        raise AssertionError(f"{name}: null result")
    try:
        raw = ctypes.string_at(pointer).decode()
    finally:
        lib.reader_free_string(pointer)
    actual = raw if rule.startswith('@js:') else json.loads(raw)
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")
    # A second ABI call confirms the process remains usable after rejection.
    pointer = lib.reader_eval(b"", b"@version")
    if not pointer:
        raise AssertionError("null version result")
    try:
        assert ctypes.string_at(pointer)
    finally:
        lib.reader_free_string(pointer)
    print(json.dumps({"case": name, "result": actual}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--case', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    if args.case is not None:
        child(library, args.case)
        return 0
    failed = 0
    for index, (name, *_rest) in enumerate(CASES):
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), '--library', str(library), '--case', str(index)],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode:
                failed += 1
                print(f"FAIL {name}: exit={result.returncode}\n{result.stderr}")
            else:
                print(f"PASS {result.stdout.strip()}")
        except subprocess.TimeoutExpired:
            failed += 1
            print(f"FAIL {name}: timeout")
    print(f"{len(CASES) - failed}/{len(CASES)} passed; library={library}")
    return int(failed != 0)


if __name__ == '__main__':
    sys.exit(main())
