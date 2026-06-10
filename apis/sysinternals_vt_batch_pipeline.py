import csv
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from apis.sysinternals_vt_report_cache import (
    load_cached_hash_ratios,
    load_existing_row_keys,
    merge_cumulative_report,
    partition_existing_report,
    shard_index_for_hash,
)
from utils.md5_hash import (
    hash_file,
    is_probably_hash_list_file,
    iter_directory_hash_records,
    iter_hash_records_from_file,
)


REPORT_COLUMNS = ["ratio", "hash", "path/to/file"]


@dataclass(slots=True)
class BatchQueryConfig:
    report_file: Path
    work_root: Path
    batch_size: int = 100
    worker_count: int = 8
    shard_count: int = 32

    def __post_init__(self):
        self.report_file = Path(self.report_file)
        self.work_root = Path(self.work_root)
        self.batch_size = max(1, int(self.batch_size))
        self.worker_count = max(1, int(self.worker_count))
        self.shard_count = max(self.worker_count, int(self.shard_count))


def iter_input_records(input_source):
    resolved_path = Path(input_source).resolve()
    if resolved_path.is_dir():
        yield from iter_directory_hash_records(str(resolved_path))
        return
    if not resolved_path.is_file():
        raise ValueError(f"Invalid input, expected a file_path or folder_path: {input_source}")
    if is_probably_hash_list_file(str(resolved_path)):
        yield from iter_hash_records_from_file(str(resolved_path))
        return
    yield hash_file(str(resolved_path)), str(resolved_path)


def partition_input_records(input_sources, shard_dir, shard_count):
    shard_dir.mkdir(parents=True, exist_ok=True)
    handles = {}
    writers = {}
    shard_counts = {shard_index: 0 for shard_index in range(shard_count)}
    total_records = 0

    try:
        for input_source in input_sources:
            for hash_value, record_path in iter_input_records(input_source):
                shard_index = shard_index_for_hash(hash_value, shard_count)
                if shard_index not in handles:
                    shard_path = shard_dir / f"input-shard-{shard_index:04d}.csv"
                    handles[shard_index] = shard_path.open(
                        "a", newline="", encoding="utf-8"
                    )
                    writers[shard_index] = csv.writer(handles[shard_index])

                writers[shard_index].writerow([hash_value, record_path])
                shard_counts[shard_index] += 1
                total_records += 1
    finally:
        for handle in handles.values():
            handle.close()

    shard_paths = [
        shard_dir / f"input-shard-{shard_index:04d}.csv"
        for shard_index, count in shard_counts.items()
        if count > 0
    ]
    return shard_paths, total_records


def shard_index_from_path(shard_path):
    return int(shard_path.stem.rsplit("-", 1)[-1])


def shard_output_paths(report_parts_dir, shard_index):
    base_name = f"report-shard-{shard_index:04d}"
    final_path = report_parts_dir / f"{base_name}.csv"
    temp_path = report_parts_dir / f"{base_name}.tmp"
    meta_path = report_parts_dir / f"{base_name}.json"
    return final_path, temp_path, meta_path


def load_completed_shard_summaries(report_parts_dir):
    completed = {}
    for meta_path in sorted(report_parts_dir.glob("report-shard-*.json")):
        try:
            summary = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        shard_name = summary.get("shard")
        output_path = Path(summary.get("output_path", ""))
        if not shard_name or not output_path.exists():
            continue
        completed[shard_name] = summary
    return completed


def process_shard(shard_path, report_parts_dir, batch_size, client_factory, existing_shard_path):
    report_parts_dir.mkdir(parents=True, exist_ok=True)
    shard_index = shard_index_from_path(shard_path)
    output_path, temp_output_path, meta_path = shard_output_paths(report_parts_dir, shard_index)
    cached_ratios = load_cached_hash_ratios(existing_shard_path)
    seen_rows = load_existing_row_keys(existing_shard_path)
    pending_records = {}
    written_rows = 0
    queried_hashes = 0
    reused_hashes = 0
    duplicate_rows = 0
    failed_hashes = 0
    client = client_factory()

    def flush_pending(writer):
        nonlocal queried_hashes, written_rows, failed_hashes
        if not pending_records:
            return

        batch_hashes = list(pending_records)
        try:
            detection_map = client.query_hashes(batch_hashes)
            queried_hashes += len(batch_hashes)
        except Exception:
            failed_hashes += len(batch_hashes)
            pending_records.clear()
            return

        for hash_value, paths in pending_records.items():
            detection_ratio = detection_map.get(hash_value, "unknown")
            cached_ratios[hash_value] = detection_ratio
            for record_path in paths:
                writer.writerow([detection_ratio, hash_value, record_path])
                written_rows += 1
        pending_records.clear()

    try:
        if temp_output_path.exists():
            temp_output_path.unlink()

        with shard_path.open("r", newline="", encoding="utf-8") as input_handle, temp_output_path.open(
            "w", newline="", encoding="utf-8"
        ) as output_handle:
            reader = csv.reader(input_handle)
            writer = csv.writer(output_handle)
            writer.writerow(REPORT_COLUMNS)

            for hash_value, record_path in reader:
                row_key = (hash_value, record_path)
                if row_key in seen_rows:
                    duplicate_rows += 1
                    continue
                seen_rows.add(row_key)

                if hash_value in cached_ratios:
                    reused_hashes += 1
                    writer.writerow([cached_ratios[hash_value], hash_value, record_path])
                    written_rows += 1
                    continue

                pending_records.setdefault(hash_value, []).append(record_path)
                if len(pending_records) >= batch_size:
                    flush_pending(writer)

            flush_pending(writer)

        os.replace(temp_output_path, output_path)
    finally:
        if temp_output_path.exists():
            temp_output_path.unlink()
        if hasattr(client, "close"):
            client.close()

    summary = {
        "shard": shard_path.name,
        "rows": written_rows,
        "queried_hashes": queried_hashes,
        "reused_hashes": reused_hashes,
        "duplicates": duplicate_rows,
        "failed_hashes": failed_hashes,
        "output_path": str(output_path),
    }
    if failed_hashes == 0:
        meta_path.write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    elif meta_path.exists():
        meta_path.unlink()
    return summary


def process_shards(shard_paths, report_parts_dir, config, existing_report_shards=None, client_factory=None):
    report_parts_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    existing_report_shards = existing_report_shards or {}
    completed_summaries = load_completed_shard_summaries(report_parts_dir)
    pending_shard_paths = []

    for shard_path in shard_paths:
        shard_name = shard_path.name
        if shard_name in completed_summaries:
            summaries.append(completed_summaries[shard_name])
        else:
            pending_shard_paths.append(shard_path)

    with ThreadPoolExecutor(max_workers=config.worker_count) as executor:
        future_map = {}
        for shard_path in pending_shard_paths:
            shard_index = shard_index_from_path(shard_path)
            future = executor.submit(
                process_shard,
                shard_path,
                report_parts_dir,
                config.batch_size,
                client_factory,
                existing_report_shards.get(shard_index),
            )
            future_map[future] = shard_path

        for future in as_completed(future_map):
            summaries.append(future.result())

    return sorted(summaries, key=lambda item: item["shard"])


def _source_signature(source):
    resolved_path = Path(source).resolve()
    try:
        stat = resolved_path.stat()
        stat_bits = f"{stat.st_size}:{stat.st_mtime_ns}"
    except OSError:
        stat_bits = "missing"
    return f"{resolved_path}:{stat_bits}"


def build_run_directory(work_root, input_sources):
    seed_names = [Path(source).stem for source in input_sources[:3]] or ["query"]
    safe_seed = "-".join(seed_names).replace(" ", "-")
    fingerprint_payload = "|".join(_source_signature(source) for source in input_sources)
    digest = hashlib.sha1(fingerprint_payload.encode("utf-8")).hexdigest()[:12]
    return work_root / f"resume-{safe_seed}-{digest}"


def run_batch_query(input_sources, config, client_factory):
    run_dir = build_run_directory(config.work_root, input_sources)
    shard_dir = run_dir / "input-shards"
    report_parts_dir = run_dir / "report-shards"
    existing_report_shards = partition_existing_report(
        config.report_file,
        run_dir / "existing-report-shards",
        config.shard_count,
    )
    shard_paths, total_records = partition_input_records(
        input_sources,
        shard_dir,
        config.shard_count,
    )
    if total_records == 0:
        return None

    summaries = process_shards(
        shard_paths,
        report_parts_dir,
        config,
        existing_report_shards=existing_report_shards,
        client_factory=client_factory,
    )
    merge_cumulative_report(report_parts_dir, config.report_file, existing_report_shards)
    return {
        "run_dir": str(run_dir),
        "report_file": str(config.report_file),
        "total_records": total_records,
        "total_shards": len(shard_paths),
        "total_rows": sum(item["rows"] for item in summaries),
        "queried_hashes": sum(item["queried_hashes"] for item in summaries),
        "reused_hashes": sum(item["reused_hashes"] for item in summaries),
        "duplicate_rows": sum(item.get("duplicates", 0) for item in summaries),
        "failed_hashes": sum(item.get("failed_hashes", 0) for item in summaries),
    }
