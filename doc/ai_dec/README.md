# Decision log

Every engineering decision, automatic or human (workflow rule h2), gets one file `decision_NNN.md`.

| # | Title | Type |
|---|-------|------|
| 001 | [Git remote and commit identity](decision_001.md) | human |
| 002 | [Debian/Ubuntu-style package layout](decision_002.md) | human |
| 003 | [Per-distro dist/ subdirectories](decision_003.md) | human |
| 004 | [Header extension: variables + request-header directive](decision_004.md) | human |
| 005 | [Python code layout](decision_005.md) | human |
| 006 | [Static module + thin nginx patch, OpenSSL unpatched](decision_006.md) (OpenSSL part superseded by 029) | human |
| 007 | [Private OPENSSLDIR with shipped openssl.cnf](decision_007.md) (superseded by 029) | human |
| 008 | [nginx module set](decision_008.md) | human |
| 009 | [Source acquisition and version selection](decision_009.md) (OpenSSL part superseded by 029) | automatic |
| 010 | [.deb assembly with debhelper](decision_010.md) | human |
| 011 | [JA4 per-connection storage: compact capped lists](decision_011.md) | human |
| 012 | [HTTP/2 signature overflow: truncate + flag variable](decision_012.md) | human |
| 013 | [Defaults: capture and header injection enabled](decision_013.md) | human |
| 014 | [JA4 capture details in the module](decision_014.md) (superseded by 030, 034) | automatic |
| 015 | [HTTP/2 hook details](decision_015.md) | automatic |
| 016 | [Directive semantics](decision_016.md) | automatic |
| 017 | [OpenSSL build options and symbol hiding](decision_017.md) (superseded by 029) | automatic |
| 018 | [Docker builds: rootless detection, build images, tree location](decision_018.md) | automatic |
| 019 | [Test strategy](decision_019.md) | automatic |
| 020 | [Debian package details](decision_020.md) | automatic |
| 021 | [build.sh bootstrap](decision_021.md) | automatic |
| 022 | [TLSFP: follow the draft, implemented separately from JA4](decision_022.md) | human |
| 023 | [TLSFP_d without supported groups: 000000000000](decision_023.md) | human |
| 024 | [X-Client-TLSFP sent by default](decision_024.md) | human |
| 025 | [TLSFP ALPN characters: lower-case, hex nibbles](decision_025.md) | human |
| 026 | [TLSFP computed eagerly, lists uncapped](decision_026.md) (capture point superseded by 030, limit by 033) | human |
| 027 | [TLSFP interpretation details](decision_027.md) | automatic |
| 028 | [TLSFP module integration](decision_028.md) | automatic |
| 029 | [Remove OpenSSL; nginx uses the distribution's TLS library](decision_029.md) | human |
| 030 | [Library-independent ClientHello capture and hashing](decision_030.md) | human |
| 031 | [Package version without the TLS library](decision_031.md) | human |
| 032 | [Remove the OpenSSL-only tools and tests](decision_032.md) | human |
| 033 | [ClientHello capture limit: 16 KiB](decision_033.md) | human |
| 034 | [Per-connection result in ngx_http_connection_t](decision_034.md) | human |
| 035 | [HTTP/3 on every target](decision_035.md) | human |
| 036 | [SSLv2-format ClientHellos: no fingerprint, refused by default](decision_036.md) | human |
| 037 | [ClientHello capture: implementation details](decision_037.md) | automatic |
| 038 | [A connection waiting for its ClientHello is not reusable](decision_038.md) | human |
| 039 | [Level-triggered event methods are tested on the ASan build only](decision_039.md) | automatic |
