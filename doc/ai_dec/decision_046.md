# 046 — A second release on the same day

- Date: 2026-11-18
- Type: human

## Context
Decision 045 names a release after the date of its build. Release `2026-11-18` has the packages of nginx 1.31.8
and 1.30.6. On the same day, nginx 1.31.9 and 1.30.7 came out with security fixes, and the packages were built
again. The tag `2026-11-18` exists already.

## Decision
- The second release of a day has the tag `<date>-2`, here `2026-11-18-2` (maintainer's choice).
- Automatic: a third release on the same day has `-3`, and so on.
- The earlier release stays as it is. The new release is marked Latest. All other rules of decision 045 apply.
