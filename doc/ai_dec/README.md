# Decision log

Every engineering decision, automatic or human (workflow rule h2), gets one file `decision_NNN.md`.

| # | Title | Type |
|---|-------|------|
| 001 | [Git remote and commit identity](decision_001.md) | human |
| 002 | [Debian/Ubuntu-style package layout](decision_002.md) | human |
| 003 | [Per-distro dist/ subdirectories](decision_003.md) | human |
| 004 | [Header extension: variables + request-header directive](decision_004.md) | human |
| 005 | [Python code layout](decision_005.md) | human |
| 006 | [Static module + thin nginx patch, OpenSSL unpatched](decision_006.md) | human |
| 007 | [Private OPENSSLDIR with shipped openssl.cnf](decision_007.md) | human |
| 008 | [nginx module set](decision_008.md) | human |
| 009 | [Source acquisition and version selection](decision_009.md) | automatic |
| 010 | [.deb assembly with debhelper](decision_010.md) | human |
| 011 | [JA4 per-connection storage: compact capped lists](decision_011.md) | human |
| 012 | [HTTP/2 signature overflow: truncate + flag variable](decision_012.md) | human |
| 013 | [Defaults: capture and header injection enabled](decision_013.md) | human |
| 014 | [JA4 capture details in the module](decision_014.md) | automatic |
| 015 | [HTTP/2 hook details](decision_015.md) | automatic |
| 016 | [Directive semantics](decision_016.md) | automatic |
| 017 | [OpenSSL build options and symbol hiding](decision_017.md) | automatic |
| 018 | [Docker builds: rootless detection, build images, tree location](decision_018.md) | automatic |
| 019 | [Test strategy](decision_019.md) | automatic |
| 020 | [Debian package details](decision_020.md) | automatic |
| 021 | [build.sh bootstrap](decision_021.md) | automatic |
| 022 | [TLSFP: follow the draft, implemented separately from JA4](decision_022.md) | human |
| 023 | [TLSFP_d without supported groups: 000000000000](decision_023.md) | human |
| 024 | [X-Client-TLSFP sent by default](decision_024.md) | human |
| 025 | [TLSFP ALPN characters: lower-case, hex nibbles](decision_025.md) | human |
| 026 | [TLSFP computed eagerly, lists uncapped](decision_026.md) | human |
| 027 | [TLSFP interpretation details](decision_027.md) | automatic |
| 028 | [TLSFP module integration](decision_028.md) | automatic |
