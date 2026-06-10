# Context Links

- [x-virus.py](/mnt/HDD/MyProject/x-vriuSs/x-virus.py)
- [apis/sysinternals_vt.py](/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt.py)

## Overview

- Priority: P1
- Status: Pending
- Goal: expose worker count while keeping existing CLI and output format intact.

## Key Insights

- User explicitly wants `-worker` only; no other CLI contract changes.
- Internal shard count can stay derived from worker count.

## Requirements

- `x-virus.py -x input.txt -worker 8`
- `x-virus.py -x dir/` still works without `-worker`

## Architecture

- Parse `-worker` once at CLI.
- Pass it through `sysinternal_vt(..., worker_count=args.worker)`.

## Related Code Files

- Modify: `/mnt/HDD/MyProject/x-vriuSs/x-virus.py`
- Modify: `/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt.py`

## Implementation Steps

1. Add parser arg.
2. Validate positive int in wrapper config.
3. Preserve current final `Done...` and `No new hashes to query` messaging.

## Todo List

- [ ] Add `-worker`
- [ ] Map worker count to pipeline config
- [ ] Keep summary wording stable

## Success Criteria

- Help text shows `-worker`.
- Worker count changes thread pool size only.

## Risk Assessment

- Risk: too many workers can trigger VT throttling.
- Mitigation: keep retry/backoff; allow env override.

## Security Considerations

- Do not accept zero/negative worker count.

## Next Steps

- Run test suite.

