# 033 — ClientHello capture limit: 16 KiB

- Date: 2026-11-17
- Type: human

## Context
With decision 030 the module peeks at the TCP socket and waits until the whole ClientHello is in the receive queue,
before the TLS library reads anything. Peeking does not consume data, so the kernel's receive window does not
open: a hello larger than the window would stall the client until `client_header_timeout`. Real clients send
less than about 2 KB (Chrome with post-quantum key shares about 1.8 KB); the largest hostile test hello is about
14.5 KB. Before, only OpenSSL's 128 KiB limit applied.

## Options
1. Handshake message up to 16 KiB, raw record bytes up to 32 KiB.
2. 32 KiB message, 64 KiB raw.
3. 64 KiB message, 128 KiB raw.

## Decision
Option 1.
- A larger hello gets no JA4 and no TLSFP (logged at info level); its handshake proceeds normally.
- The same message limit applies to QUIC.
- TLSFP lists stay uncapped within that limit (decision 026); the JA4 1024-entry cap (decision 011) is unchanged.
