# Context Links

- [README.md](/mnt/HDD/MyProject/x-vriuSs/README.md)
- [x-virus.py](/mnt/HDD/MyProject/x-vriuSs/x-virus.py)
- [apis/sysinternals_vt.py](/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt.py)
- Compiled references recovered from `apis/__pycache__/sysinternals_vt_*.cpython-313.pyc`

## Overview

- Priority: P1
- Status: Pending
- Goal: restore the intended shard + worker VT query design before touching CLI.

## Key Insights

- Current source is single-threaded and hits SQLite/cache on every record.
- Compiled tests show a newer pipeline existed: shard input by hash, process shards with `ThreadPoolExecutor`, merge report shards back into `report_query.csv`.
- Test expectations require: hash-list header detection, binary-file fallback to local hashing, cached report reuse, response mapping by hash key, not response order.

## Requirements

- Keep file input and directory input working.
- Keep final report columns: `ratio,hash,path/to/file`.
- Add worker control without breaking existing `-x` usage.

## Architecture

- `utils/md5_hash.py`: robust hash-list detection + iterators.
- `apis/sysinternals_vt_http_client.py`: VT batch client with retry/backoff.
- `apis/sysinternals_vt_report_cache.py`: shard routing + report merge.
- `apis/sysinternals_vt_batch_pipeline.py`: partition, parallel shard processing, summary.
- `apis/sysinternals_vt.py`: compatibility wrapper for CLI.

## Related Code Files

- Modify: `/mnt/HDD/MyProject/x-vriuSs/utils/md5_hash.py`
- Modify: `/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt.py`
- Modify: `/mnt/HDD/MyProject/x-vriuSs/x-virus.py`
- Create: `/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt_http_client.py`
- Create: `/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt_report_cache.py`
- Create: `/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt_batch_pipeline.py`
- Create: `/mnt/HDD/MyProject/x-vriuSs/test/test.py`

## Implementation Steps

1. Reconstruct helpers from compiled behavior.
2. Keep deterministic payload and hash-keyed response mapping.
3. Preserve report merge semantics and resume behavior.

## Todo List

- [ ] Restore utils parsing helpers
- [ ] Restore VT client
- [ ] Restore shard/merge pipeline

## Success Criteria

- Input hash-list with header is parsed correctly.
- Existing report entries are reused.
- Unique hashes are queried once per shard batch.

## Risk Assessment

- Risk: changing single-column hash-list path semantics.
- Mitigation: keep report columns unchanged, default missing path to `unknown`.

## Security Considerations

- Do not log API key.
- Bound worker count and batch size.

## Next Steps

- Wire `-worker` into CLI.
- Run unit tests and compile checks.

