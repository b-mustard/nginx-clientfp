# 044 — The echo server shows its public address

- Date: 2026-11-18
- Type: human

## Context
`examples/echo_server.py` printed `https://<this machine>:8443/` as the address for other machines, and the reader
had to find the address. The maintainer asked for the public address, from `https://cloudflare.com/cdn-cgi/trace`,
in its place, and for the TLSFP in the log line of each request. The integration tests start the echo server in
every test container.

## Decision
- At start, after it binds `127.0.0.1:8081`, the echo server sends one request to
  `https://cloudflare.com/cdn-cgi/trace`, with a timeout of 3 seconds. The `ip=` value of the reply, accepted only
  if it is an IP address (an IPv6 address is written in brackets), replaces `<this machine>`.
- The banner stays one line and comes after the lookup. Requests that arrive during the lookup wait in the listen
  queue (maintainer's choice, over printing at once and the address later).
- If the lookup fails, the banner shows `<this machine>` as before, and a line on stderr gives the reason.
- The option `--no-lookup` skips the request (maintainer's choice, over an environment variable). The integration
  tests use it, so that a test run sends no requests to Cloudflare.
- The log line of each request shows `tlsfp=` after `ja4=`.
- Automatic: the guide says that the echo server makes this one outgoing request, and that the address is the one
  the internet sees, which machines on the same local network may not reach.
