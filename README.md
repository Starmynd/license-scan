# license-scan

Identify the licenses of Python projects on disk. Walks a directory,
finds license-bearing files (`LICENSE*`, `COPYING*`, `NOTICE*`,
`UNLICENSE*`) and SPDX tags, classifies them by fingerprint, prints a
per-project summary. One file, standard library only.

## Recognized licenses

MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, GPL-2.0, GPL-3.0,
MPL-2.0, Unlicense - plus any explicit
`SPDX-License-Identifier: <id>` tag, which always wins over the
fingerprint heuristics. Unrecognizable license files are listed as `?`
so you know where to look.

## Usage

```console
$ license-scan ~/src
proj-a                        MIT (1)
proj-b                        Apache-2.0 (1)
vendored-thing                NONE FOUND

$ license-scan --list ~/src/proj-c
proj-c                        BSD-3-Clause (1), GPL-2.0 (1)
    BSD-3-Clause   LICENSE
    GPL-2.0        COPYING

$ license-scan setup.py       # classify a single file
setup.py                      Apache-2.0 (1)
```

Exit code is always 0: this is a reporting tool, not a gate. Pipe
through `grep -c "NONE FOUND"` if you need one.

## Python API

```python
from license_scan import scan_tree, scan_project, sniff, render

sniff("LICENSE")               # "MIT" or None
scan_project("~/src/proj-a")   # {"name": ..., "licenses": {...}, "unknown": [...]}
scan_tree("~/src")             # root + every subdir that has license files
render(results, show_files=True)
```

`scan_tree` scans the given directory plus immediate subdirectories
that contain license files - the common "one folder per project"
layout - without descending into `.hidden` or deep nesting.

## Testing

```console
$ python3 license_scan.py --test
selftest: failures=0
```

Covers fingerprint detection (MIT, Apache, BSD-3 ordering, ISC), SPDX
tags, unknown-file reporting, projects with no license, relative-path
rendering and single-file mode.

## License

MIT
