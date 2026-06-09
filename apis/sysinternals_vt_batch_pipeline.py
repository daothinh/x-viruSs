import csv
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from apis.sysinternals_vt_http_client import SysinternalsVTClient
from utils.md5_hash import (
    hash_file,
    is_probably_hash_list_file,
    iter_directory_hash_records,
    iter_hash_records_from_file,
)


@dataclass(slots=True)
class BatchQueryConfig:
    report_file: Path
    work_root: Path
    batch_size: int = 100
    worker_count: int = 8
    shard_count: int = 32


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
                shard_index = int(hashlib.md5(hash_value.encode("utf-8")).hexdigest(), 16) % shard_count
                if shard_index not in handles:
                    shard_path = shard_dir / f"input-shard-{shard_index:04d}.csv"
                    handles[shard_index] = shard_path.open("a", newline="", encoding="utf-8")
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


def process_shard(shard_path, output_path, batch_size, client_factory):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cache = {}
    pending_records = {}
    written_rows = 0
    queried_hashes = 0
    client = client_factory()

    def flush_pending(writer):
        nonlocal queried_hashes, written_rows
        if not pending_records:
            return

        batch_hashes = list(pending_records)
        detection_map = client.query_hashes(batch_hashes)
        queried_hashes += len(batch_hashes)

        for hash_value, paths in pending_records.items():
            detection_ratio = detection_map.get(hash_value, "unknown")
            cache[hash_value] = detection_ratio
            for record_path in paths:
                writer.writerow([detection_ratio, hash_value, record_path])
                written_rows += 1

        pending_records.clear()

    with shard_path.open("r", newline="", encoding="utf-8") as input_handle, output_path.open(
        "w", newline="", encoding="utf-8"
    ) as output_handle:
        reader = csv.reader(input_handle)
        writer = csv.writer(output_handle)
        writer.writerow(["ratio", "hash", "path/to/file"])

        for hash_value, record_path in reader:
            if hash_value in cache:
                writer.writerow([cache[hash_value], hash_value, record_path])
                written_rows += 1
                continue

            pending_records.setdefault(hash_value, []).append(record_path)
            if len(pending_records) >= batch_size:
                flush_pending(writer)

        flush_pending(writer)

    return {
        "shard": shard_path.name,
        "rows": written_rows,
        "queried_hashes": queried_hashes,
        "output_path": str(output_path),
    }


def process_shards(shard_paths, report_parts_dir, config, client_factory=SysinternalsVTClient):
    report_parts_dir.mkdir(parents=True, exist_ok=True)
    summaries = []

    with ThreadPoolExecutor(max_workers=config.worker_count) as executor:
        future_map = {}
        for shard_path in shard_paths:
            shard_suffix = shard_path.stem.replace("input-", "")
            output_path = report_parts_dir / f"report-{shard_suffix}.csv"
            future = executor.submit(process_shard, shard_path, output_path, config.batch_size, client_factory)
            future_map[future] = shard_path

        for future in as_completed(future_map):
            summaries.append(future.result())

    return sorted(summaries, key=lambda item: item["shard"])


def merge_shard_reports(report_parts_dir, report_file):
    report_file.parent.mkdir(parents=True, exist_ok=True)
    with report_file.open("w", newline="", encoding="utf-8") as output_handle:
        writer = csv.writer(output_handle)
        writer.writerow(["ratio", "hash", "path/to/file"])

        for part_path in sorted(report_parts_dir.glob("report-shard-*.csv")):
            with part_path.open("r", newline="", encoding="utf-8") as input_handle:
                reader = csv.reader(input_handle)
                next(reader, None)
                for row in reader:
                    writer.writerow(row)


def build_run_directory(work_root, input_sources):
    seed_names = [Path(source).stem for source in input_sources[:3]] or ["query"]
    safe_seed = "-".join(seed_names).replace(" ", "-")
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    return work_root / f"{timestamp}-{safe_seed}"


def run_batch_query(input_sources, config, client_factory=SysinternalsVTClient):
    run_dir = build_run_directory(config.work_root, input_sources)
    shard_dir = run_dir / "input-shards"
    report_parts_dir = run_dir / "report-shards"

    shard_paths, total_records = partition_input_records(input_sources, shard_dir, config.shard_count)
    if total_records == 0:
        return None

    summaries = process_shards(shard_paths, report_parts_dir, config, client_factory=client_factory)
    merge_shard_reports(report_parts_dir, config.report_file)

    return {
        "run_dir": str(run_dir),
        "report_file": str(config.report_file),
        "total_records": total_records,
        "total_shards": len(shard_paths),
        "total_rows": sum(item["rows"] for item in summaries),
        "queried_hashes": sum(item["queried_hashes"] for item in summaries),
    }
