# 020 — Debian package details not covered by decisions 002/008/010

- Date: 2026-11-16
- Type: automatic

- Base the maintainer files on Ubuntu's `nginx`: the `init` script, `default`, `logrotate`, the systemd unit,
  `sites-available/default`, the `snippets/`, `proxy_params`, the vim addon and the ufw profiles. Add a ufw
  `Nginx QUIC` profile, because HTTP/3 is enabled (decision 008).
- `Conflicts`/`Replaces`/`Provides: nginx` against the distribution's nginx packages: both own `/usr/sbin/nginx`
  and `/etc/nginx`.
- Source format `1.0`, binary-only builds (`dpkg-buildpackage -b`). There is no source package to upload, and
  native/quilt formats would need a tarball we do not ship.
- The maintainer address is the project placeholder `noreply@example.com` (workflow rule g2). Accepted lintian
  tags are listed with reasons in `packager/lintian-suppress`.
- The examples (`echo_server.py`, `nginx-echo.conf`) and the module reference are installed to
  `/usr/share/doc/nginx-clientfp/`. A missing one fails the build.
- The `-dbgsym` package is kept next to the `.deb` in `dist/<target>/`.
