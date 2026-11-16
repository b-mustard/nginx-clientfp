# 001 — Git remote and commit identity

- Date: 2026-11-16
- Type: human

## Context
Rule g4 asks to commit and push every logical change. The repository had no remote.

## Options
1. Local commits only until a remote is provided.
2. User supplies a remote URL now.

## Decision
Option 1. Commits are local; pushing starts once a remote (`origin`) is configured.
Commits use the repo-local identity `Claude Opus 5.5 <noreply@example.com>` (g1), with no `Co-authored-by` trailer.
