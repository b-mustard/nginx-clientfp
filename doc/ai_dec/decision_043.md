# 043 — License: BSD-2-Clause

- Date: 2026-11-18
- Type: human

## Context
The repository had no license file. Only the package's `debian/copyright` named a license, BSD-2-clause, for the
module and the packaging. The maintainer asked to license the code and the project under the 2-clause BSD license,
the license of nginx itself.

Two documents in `doc/` come from other sources: `doc/ja4_sig.md` is a condensed version of FoxIO's `JA4.md`, which
FoxIO licenses under BSD-3-Clause, and `doc/nDPI_TLS_Fingerprint.md` is ntop's draft under CC BY 4.0.

## Decision
- The project is under BSD-2-Clause. The copyright holder is "nginx-clientfp contributors", year 2026, in
  `LICENSE`, in the file headers and in `debian/copyright`. This puts no personal name in the public repository.
- `LICENSE` at the top of the repository holds the standard text, without additions, so that tools that detect the
  license (GitHub's among them) recognize it. The exceptions are listed in the License section of `README.md`.
- Each code file starts with two comment lines:

  ```
  SPDX-License-Identifier: BSD-2-Clause
  Copyright (c) 2026 nginx-clientfp contributors
  ```

  Code files are the C sources and headers, Python, shell, Dockerfiles, the module's `config`, our nginx
  configuration files, the valgrind suppressions, `packager/lintian-suppress` and the nginx patches. In a patch
  the lines come before the first `diff --git`, where `git apply` ignores text. A unit test checks every tracked
  code file, so a new file cannot miss them.
- Not in that scope: `packager/debian/`, which holds files from Debian's nginx packaging and is covered by
  `debian/copyright`; documentation and data files, covered by `LICENSE`.
- `doc/ja4_sig.md` is treated as a work derived from FoxIO's `JA4.md`: it stays under BSD-3-Clause and carries
  FoxIO's notice (Copyright (c) 2026 FoxIO).
- `doc/nDPI_TLS_Fingerprint.md` stays under CC BY 4.0, as the file states.
- Automatic, one sensible answer: `license = "BSD-2-Clause"` in `pyproject.toml` (this form needs setuptools 77 or
  later), and `Source:` in `debian/copyright` names the public repository.
