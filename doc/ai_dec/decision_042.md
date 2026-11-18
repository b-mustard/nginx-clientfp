# 042 — Public repository `origin_pub`

- Date: 2026-11-18
- Type: human

## Context
The repository so far had one remote, `origin`, a private repository (decision 001). The maintainer has published a
public repository on GitHub.

## Decision
- The public repository is the remote `origin_pub`: `https://github.com/b-mustard/nginx-clientfp`.
- The address of the private repository must not leak: it does not appear in commits, code, docs, decision records or
  anything else that can reach `origin_pub`. Text that needs to refer to it says "the private repository".
- The credentials for `origin_pub` are in the file `.secrets` at the top of the working tree. Git ignores it, and its
  contents are never committed, printed or logged. A credential helper in the local git configuration reads the file
  when git needs it, so the token is in neither the remote URL nor a credential store.
- Pushing stays off for both remotes until the maintainer says otherwise.
