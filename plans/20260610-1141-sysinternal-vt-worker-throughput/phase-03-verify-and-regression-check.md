# Context Links

- [test/test.py](/mnt/HDD/MyProject/x-vriuSs/test/test.py)
- [README.md](/mnt/HDD/MyProject/x-vriuSs/README.md)

## Overview

- Priority: P1
- Status: Pending
- Goal: verify recovered behavior and worker flag without guessing.

## Key Insights

- Repo has no live source tests, but compiled tests provide exact expected behavior.
- Stdlib `unittest` is enough; no new dependency needed.

## Requirements

- Recreate behavior tests from compiled fixtures.
- Run compile checks on modified Python files.

## Architecture

- Local HTTP test server simulates VT batch endpoint.
- Unit tests verify parsing, batching, resume cache, and response mapping.

## Related Code Files

- Create: `/mnt/HDD/MyProject/x-vriuSs/test/test.py`

## Implementation Steps

1. Restore tests from compiled behavior.
2. Run `python -m unittest test.test`.
3. Run `python -m py_compile ...`.

## Todo List

- [ ] Restore tests
- [ ] Run unit tests
- [ ] Run compile checks

## Success Criteria

- Unit tests pass.
- CLI help shows `-worker`.
- No syntax errors.

## Risk Assessment

- Risk: hidden legacy behavior not covered by recovered tests.
- Mitigation: keep wrapper interface small and report format unchanged.

## Security Considerations

- Test server is local only.

## Next Steps

- Update README option table.
