# VirusTotal Batch Query Upgrade

Status: completed
Priority: high

Goal: upgrade `-x` so it can process very large hash sources with a streaming batch pipeline, concurrent query workers, and a deterministic final merge.

Phases:
- [completed] [phase-01-upgrade-vt-batch-pipeline.md](/mnt/HDD/MyProject/x-vriuSs/plans/20260609-virustotal-batch-query-upgrade/phase-01-upgrade-vt-batch-pipeline.md)
- [completed] Implement and validate compile/test path
- [completed] Update README usage notes for large-scale query runs

Key constraints:
- Keep `-x` backward-compatible for directory input and hash-list input.
- Do not hold the full 4M-hash dataset in memory.
- Avoid concurrent writes to the same CSV.
- Keep output merge deterministic and resumable enough for repeated runs.

Validation:
- Unit tests for parser, sharding, batching, and merge behavior.
- Compile check with `python -m compileall`.
- Live smoke audit against current Sysinternals VT endpoint via `x-virus.py -x`.

Risks:
- API-side rate limiting can cap throughput even with local concurrency.
- Existing input semantics for `-x` are ambiguous between binary file and hash-list file.

Unresolved questions:
- None at planning time.
