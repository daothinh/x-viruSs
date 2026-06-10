#!/usr/bin/env python
import os
from pathlib import Path

from dotenv import load_dotenv

from apis.sysinternals_vt_batch_pipeline import BatchQueryConfig, run_batch_query
from apis.sysinternals_vt_http_client import SysinternalsVTClient

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
REPORT_FILE = os.path.join(BASE_DIR, "data", "report_query.csv")


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name, default):
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


DEFAULT_BATCH_SIZE = max(1, _env_int("SYSINTERNAL_BATCH_SIZE", 100))
DEFAULT_WORKER_COUNT = max(1, _env_int("SYSINTERNAL_WORKER_COUNT", 8))
DEFAULT_SHARD_COUNT = max(
    DEFAULT_WORKER_COUNT,
    _env_int("SYSINTERNAL_SHARD_COUNT", DEFAULT_WORKER_COUNT * 4),
)
REQUEST_TIMEOUT = _env_float("SYSINTERNAL_REQUEST_TIMEOUT", 60)
MAX_RETRIES = max(1, _env_int("SYSINTERNAL_MAX_RETRIES", 3))
BACKOFF_SECONDS = _env_float("SYSINTERNAL_QUERY_DELAY", 2)
WORK_ROOT = Path(os.getenv("SYSINTERNAL_WORK_ROOT", os.path.join(BASE_DIR, "data", "sysinternals-vt-runs")))


def _build_client():
    return SysinternalsVTClient(
        timeout=REQUEST_TIMEOUT,
        max_retries=MAX_RETRIES,
        backoff_seconds=BACKOFF_SECONDS,
    )


def sysinternal_vt(input_source, worker_count=None):
    try:
        resolved_worker_count = DEFAULT_WORKER_COUNT if worker_count is None else int(worker_count)
        if resolved_worker_count < 1:
            raise ValueError("-worker must be greater than 0")
        config = BatchQueryConfig(
            report_file=Path(REPORT_FILE),
            work_root=WORK_ROOT,
            batch_size=DEFAULT_BATCH_SIZE,
            worker_count=resolved_worker_count,
            shard_count=max(DEFAULT_SHARD_COUNT, resolved_worker_count * 4),
        )
        stats = run_batch_query([input_source], config, client_factory=_build_client)
    except ValueError as ex:
        print(ex)
        return

    if not stats:
        print("No new hashes to query")
    else:
        print(
            "Done. Processed {total_records} rows, queried {queried_hashes} unique hashes, "
            "reused {reused_hashes} cached rows, wrote {total_rows} rows, "
            "skipped {duplicate_rows} duplicates, failed {failed_hashes} hashes".format(
                **stats
            )
        )
