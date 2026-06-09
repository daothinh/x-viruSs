import os
from pathlib import Path

from apis.sysinternals_vt_batch_pipeline import BatchQueryConfig, run_batch_query


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_FILE = BASE_DIR / "data" / "report_query.csv"
DEFAULT_WORK_ROOT = BASE_DIR / "data" / "vt_query_runs"


def read_int_setting(value, env_name, default_value, minimum=1, maximum=None):
    raw_value = value if value is not None else os.getenv(env_name, str(default_value))
    parsed_value = int(raw_value)
    if parsed_value < minimum:
        parsed_value = minimum
    if maximum is not None and parsed_value > maximum:
        parsed_value = maximum
    return parsed_value


def sysinternal_vt(
    input_sources,
    report_file=None,
    work_dir=None,
    batch_size=None,
    worker_count=None,
    shard_count=None,
):
    source_list = [input_sources] if isinstance(input_sources, str) else list(input_sources)
    if not source_list:
        print("No input sources were provided")
        return None

    resolved_report_file = Path(report_file or DEFAULT_REPORT_FILE).resolve()
    resolved_work_root = Path(work_dir or DEFAULT_WORK_ROOT).resolve()
    resolved_work_root.mkdir(parents=True, exist_ok=True)

    resolved_worker_count = read_int_setting(
        worker_count,
        "VT_QUERY_WORKERS",
        min(16, max(4, (os.cpu_count() or 4) * 2)),
    )
    resolved_batch_size = read_int_setting(batch_size, "VT_QUERY_BATCH_SIZE", 100, maximum=100)
    resolved_shard_count = read_int_setting(
        shard_count,
        "VT_QUERY_SHARDS",
        max(16, resolved_worker_count * 4),
    )

    config = BatchQueryConfig(
        report_file=resolved_report_file,
        work_root=resolved_work_root,
        batch_size=resolved_batch_size,
        worker_count=resolved_worker_count,
        shard_count=resolved_shard_count,
    )
    summary = run_batch_query(source_list, config)

    if not summary:
        print("No valid hashes found to query")
        return None

    print(
        "Prepared "
        f"{summary['total_records']} records, reused {summary['reused_hashes']} cached rows, "
        f"queried {summary['queried_hashes']} unique hashes, merged {summary['total_rows']} current rows "
        f"into {summary['report_file']}"
    )
    print(f"Shard workdir: {summary['run_dir']}")
    return summary
