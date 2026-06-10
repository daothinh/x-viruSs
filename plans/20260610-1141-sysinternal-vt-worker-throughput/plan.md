---
title: "Sysinternal VT Worker Throughput Plan"
description: "Restore the workerized Sysinternals VT batch pipeline and expose -worker without changing report/output shape."
status: pending
priority: P1
effort: 5h
branch: master
tags: [feature, backend, performance]
created: 2026-06-10
---

# Sysinternal VT Worker Throughput Plan

## Overview

Add `-worker` to the CLI. Keep current input formats. Keep `data/report_query.csv` and current user-facing summary shape. Replace the single-thread SQLite-heavy VT flow with the shard + worker pipeline recovered from the compiled tests.

## Phases

| # | Phase | Status | Effort | Link |
|---|-------|--------|--------|------|
| 1 | Recover worker pipeline behavior | Pending | 1h | [phase-01](./phase-01-recover-worker-pipeline.md) |
| 2 | Implement CLI + pipeline wiring | Pending | 2h | [phase-02](./phase-02-implement-cli-and-pipeline.md) |
| 3 | Verify with unit tests + compile checks | Pending | 2h | [phase-03](./phase-03-verify-and-regression-check.md) |

## Dependencies

- Existing `x-virus.py` CLI contract
- `data/report_query.csv` report layout
- Current VT env vars: `URL_SYSINTERNAL_QUERY`, `SYSINTERNAL_API_KEY`, request tuning vars

