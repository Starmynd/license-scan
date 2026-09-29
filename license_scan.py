#!/usr/bin/env python3
"""license-scan - identify licenses of Python projects on disk.

Walks a directory tree, finds license-bearing files (LICENSE*, COPYING*,
NOTICE*, and any file carrying an SPDX `SPDX-License-Identifier:` tag),
classifies each by fingerprint, and prints a per-project summary.

Recognized licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
GPL-2.0-only/GPL-2.0, GPL-3.0-only/GPL-3.0, Unlicense, MPL-2.0.
Anything else is reported as Unknown (with the file that needs a look).
Exit code is always 0 - this is a reporting tool.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

LICENSE_FILE_RE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE)",
                             re.IGNORECASE)
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9+.\-]+)")

# ordered: first match wins; Apache and GPL checked before BSD/ISC
FINGERPRINTS: list[tuple[str, re.Pattern[str]]] = [
    ("Apache-2.0", re.compile(r"Apache License\s+Version 2\.0", re.I)),
    ("GPL-3.0", re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 3", re.I)),
    ("GPL-2.0", re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 2", re.I)),
    ("MPL-2.0", re.compile(r"Mozilla Public License(,)? Version 2\.0", re.I)),
    ("MIT", re.compile(r"Permission is hereby granted, free of charge", re.I)),
    ("ISC", re.compile(r"Permission to use, copy, modify, and/or distribute", re.I)),
    ("BSD-3-Clause", re.compile(r"Redistribution and use in source and binary forms",
                                re.I)),
    ("BSD-2-Clause", re.compile(r"Redistribution and use in source and binary",
                                re.I)),
    ("Unlicense", re.compile(r"This is free and unencumbered software released"
                             r" into the public domain", re.I)),
]


def sniff(path: str) -> str | None:
    """Classify one file; returns the license id or None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(8192)
    except OSError:
        return None
    tag = SPDX_RE.search(head)
    if tag:
        return tag.group(1)
    for name, pattern in FINGERPRINTS:
        if pattern.search(head):
            return name
    return None


def find_license_files(root: str) -> list[str]:
    """License-bearing files directly inside `root` (not recursive)."""
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    return [os.path.join(root, n) for n in names if LICENSE_FILE_RE.match(n)
            and os.path.isfile(os.path.join(root, n))]


def scan_project(root: str) -> dict:
    """Scan one project directory.

    Returns {name, licenses: {id: [files]}, unknown: [files]}.
    """
    name = os.path.basename(os.path.abspath(root)) or root
    result: dict = {"name": name, "licenses": {}, "unknown": []}
    seen: set[str] = set()

    for path in find_license_files(root):
        lic = sniff(path)
        rel = os.path.basename(path)
        seen.add(rel.lower())
        if lic:
            result["licenses"].setdefault(lic, []).append(rel)
        else:
            result["unknown"].append(rel)

    # also honor SPDX tags in the package's main module / setup.py / pyproject
    for extra in ("setup.py", "pyproject.toml", "README.md", "README.rst"):
        path = os.path.join(root, extra)
        if not os.path.isfile(path):
            continue
        lic = sniff(path)
        if lic and not any(l.upper().startswith(lic.upper())
                           for l in result["licenses"]):
            result["licenses"].setdefault(lic, []).append(f"{extra} (SPDX)")
    return result


def scan_tree(root: str) -> list[dict]:
    """Scan `root` itself plus every immediate subdirectory project."""
    results = [scan_project(root)]
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return results
    for entry in entries:
        path = os.path.join(root, entry)
        if os.path.isdir(path) and not entry.startswith("."):
            if find_license_files(path):
                results.append(scan_project(path))
    return results


def render(results: list[dict], show_files: bool = False) -> list[str]:
    lines = []
    for res in results:
        if res["licenses"]:
            summary = ", ".join(f"{k} ({len(v)})"
                                for k, v in sorted(res["licenses"].items()))
        else:
            summary = "NONE FOUND"
        lines.append(f"{res['name']:<28} {summary}")
        if show_files:
            for lic in sorted(res["licenses"]):
                for f in res["licenses"][lic]:
                    lines.append(f"    {lic:<14} {f}")
        for f in res["unknown"]:
            lines.append(f"    {'?':<14} {f} (unrecognized)")
    return lines


def _selftest() -> int:
    import tempfile

    failed = 0

    def check(cond: bool, label: str) -> None:
        nonlocal failed
        print(("PASS " if cond else "FAIL ") + label)
        if not cond:
            failed += 1

    MIT = "Permission is hereby granted, free of charge, to any person."
    APACHE = "Apache License\nVersion 2.0, January 2004"
    BSD3 = "Redistribution and use in source and binary forms, with or without"
    ISC = "Permission to use, copy, modify, and/or distribute this software"

    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "proj-mit"))
        os.makedirs(os.path.join(tmp, "proj-apache"))
        os.makedirs(os.path.join(tmp, "proj-unknown"))
        os.makedirs(os.path.join(tmp, "proj-none"))
        os.makedirs(os.path.join(tmp, ".hidden"))

        with open(os.path.join(tmp, "proj-mit", "LICENSE"), "w") as fh:
            fh.write(MIT)
        with open(os.path.join(tmp, "proj-apache", "LICENSE.txt"), "w") as fh:
            fh.write(APACHE)
        with open(os.path.join(tmp, "proj-unknown", "COPYING"), "w") as fh:
            fh.write("do whatever, who reads these anyway")
        with open(os.path.join(tmp, "proj-none", "code.py"), "w") as fh:
            fh.write("print(1)\n")
        # SPDX tag wins over an unrecognizable file body
        with open(os.path.join(tmp, "proj-unknown", "NOTICE"), "w") as fh:
            fh.write("SPDX-License-Identifier: BSD-3-Clause\n" + BSD3)

        results = scan_tree(tmp)
        by_name = {r["name"]: r for r in results}

        check("proj-mit" in by_name and by_name["proj-mit"]["licenses"].get("MIT"),
              "MIT detected by fingerprint")
        check(by_name["proj-apache"]["licenses"].get("Apache-2.0"),
              "Apache-2.0 detected")
        check(by_name["proj-unknown"]["licenses"].get("BSD-3-Clause"),
              "SPDX tag on NOTICE recognized")
        check(any(u == "COPYING" for u in by_name["proj-unknown"]["unknown"]),
              "unrecognized COPYING reported as unknown")
        check("proj-none" not in by_name or
              not by_name["proj-none"]["licenses"],
              "project without license files skipped or empty")

        lines = render(results, show_files=True)
        joined = "\n".join(lines)
        check("NONE FOUND" in joined or "proj-mit" in joined,
              "render produces a summary")
        check(not any("tmp" in ln for ln in lines if ln.startswith("    ")),
              "render shows relative file names only")

    # BSD-3 must not be shadowed by the looser BSD-2 pattern (order check)
    lic = None
    for name, pattern in FINGERPRINTS:
        if pattern.search(BSD3):
            lic = name
            break
    check(lic == "BSD-3-Clause", "BSD-3 wins over BSD-2 by ordering")

    print(f"selftest: failures={failed}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--test" in argv:
        return _selftest()

    ap = argparse.ArgumentParser(
        prog="license-scan",
        description="Identify licenses of projects on disk.")
    ap.add_argument("roots", nargs="*", default=["."],
                    help="files/dirs to scan (default: .)")
    ap.add_argument("--list", action="store_true",
                    help="show the files behind each verdict")
    args = ap.parse_args(argv)

    for root in args.roots:
        if os.path.isdir(root):
            results = scan_tree(root)
        else:
            lic = sniff(root)
            results = [{"name": os.path.basename(root),
                        "licenses": {lic: [os.path.basename(root)]} if lic else {},
                        "unknown": [] if lic else [os.path.basename(root)]}]
        print("\n".join(render(results, show_files=args.list)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
