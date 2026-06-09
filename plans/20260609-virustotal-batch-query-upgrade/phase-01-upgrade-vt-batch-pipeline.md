# Phase 01: Upgrade VT Batch Pipeline

Context links:
- [README.md](/mnt/HDD/MyProject/x-vriuSs/README.md)
- [x-virus.py](/mnt/HDD/MyProject/x-vriuSs/x-virus.py)
- [apis/sysinternals_vt.py](/mnt/HDD/MyProject/x-vriuSs/apis/sysinternals_vt.py)
- [utils/md5_hash.py](/mnt/HDD/MyProject/x-vriuSs/utils/md5_hash.py)

Overview:
- Priority: high
- Status: completed
- Brief: replace the current sequential VT query loop with a streaming, shard-based worker pipeline.

Key insights:
- Live audit confirmed the endpoint returns `data[].hash`, `found`, and `detection_ratio`.
- Current code sleeps a fixed 2 seconds after each batch and re-reads the whole CSV repeatedly.
- Current `-x` handling misclassifies a normal file path as a hash-list file.

Requirements:
- Support large hash-list files without loading everything into memory.
- Support directory input and single binary-file input.
- Split source input into smaller batch files or logical shards.
- Run multiple worker threads through the VT query core.
- Merge shard outputs into one final report.
- Preserve accurate `(ratio, hash, path/to/file)` output rows.

Architecture:
- Normalize input entries as `(hash, path)` records.
- Partition records into deterministic shard files by hash.
- Process shards in parallel workers; each worker groups unique hashes into VT request batches.
- Write one output file per shard; merge all shard outputs at the end.

Related code files:
- Modify: `x-virus.py`, `apis/sysinternals_vt.py`, `utils/md5_hash.py`, `README.md`, `.env.example`, `test/test.py`
- Create: `apis/sysinternals_vt_batch_pipeline.py`, `apis/sysinternals_vt_http_client.py`
- Delete: none

Implementation steps:
1. Fix input normalization for directory, binary file, and hash-list file sources.
2. Add shard-writer stage for large input streaming.
3. Add concurrent VT batch worker core with retry and backoff.
4. Add deterministic shard merge into the final CSV report.
5. Add tests for large-scale pipeline behavior and response parsing.
6. Run compile/tests and one live smoke audit.

Todo list:
- [x] Normalize `-x` input modes correctly
- [x] Implement shard splitting
- [x] Implement concurrent workers
- [x] Implement merge stage
- [x] Add tests
- [x] Update README

Success criteria:
- `-x` can process hash-list input via concurrent batched requests.
- Output is merged into one final CSV with a single header.
- No shared-file write races.
- Compile and tests pass.

Risk assessment:
- VT partner endpoint rate limits can reduce effective worker count.
- Very large duplicate-heavy files can still inflate disk I/O during sharding.

Security considerations:
- Do not log or print API keys.
- Treat failed or malformed responses as retryable or `unknown` without corrupting the output.

Next steps:
- Monitor real-world VT rate limits and tune `--workers` / `--shards` accordingly.
- Add resume semantics only if operational runs require checkpoint restart.

Unresolved questions:
- None.
