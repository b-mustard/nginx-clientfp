# 038 — A connection waiting for its ClientHello is not reusable

- Date: 2026-11-18
- Type: human

## Context
nginx keeps idle connections (waiting for a client's first byte, or for the next request on a keepalive
connection) in a reusable queue. When a worker runs short of connections (at most 1/16 of `worker_connections`
free), it closes the oldest reusable ones to make room. Stock nginx takes a connection out of that queue as soon as
the first byte of a TLS handshake arrives, so a handshake in progress is never closed this way, and stub_status no
longer counts it as "Waiting".

The capture of decision 030 waits for the rest of the ClientHello before the TLS connection is created. As first
written (decision 037), that wait reused nginx's code for waiting for the first byte, which left the connection
reusable: when connections ran short, nginx could close a client whose hello had partly arrived.

## Options
1. Keep it reusable: a hello that arrives slowly is treated like an idle connection.
2. Match stock nginx: not reusable once the first byte of a TLS handshake has arrived.

## Decision
Option 2. While the module waits for the ClientHello, the connection is not reusable, as during the handshake.
The wait stays bounded by `client_header_timeout` (the timer that also bounds the handshake; new data does not
restart it), by 64 peeks of an incomplete hello, and by the client closing its side.
