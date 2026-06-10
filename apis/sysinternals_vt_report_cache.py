import csv
import hashlib


REPORT_COLUMNS = ["ratio", "hash", "path/to/file"]


def shard_index_for_hash(hash_value, shard_count):
    digest = hashlib.md5(hash_value.encode("utf-8")).hexdigest()
    return int(digest, 16) % shard_count


def normalize_report_ratio(value):
    if value is None:
        return "unknown"
    ratio = value.strip()
    return ratio or "unknown"


def _open_shard_writer(shard_dir, prefix, shard_index, handles, writers, shard_paths):
    if shard_index not in writers:
        shard_path = shard_dir / f"{prefix}-{shard_index:04d}.csv"
        handle = shard_path.open("w", newline="", encoding="utf-8")
        writer = csv.writer(handle)
        writer.writerow(REPORT_COLUMNS)
        handles[shard_index] = handle
        writers[shard_index] = writer
        shard_paths[shard_index] = shard_path
    return writers[shard_index]


def partition_existing_report(report_file, shard_dir, shard_count):
    if not report_file.exists() or report_file.stat().st_size == 0:
        return {}

    shard_dir.mkdir(parents=True, exist_ok=True)
    shard_paths = {}
    handles = {}
    writers = {}

    try:
        with report_file.open("r", newline="", encoding="utf-8") as input_handle:
            reader = csv.DictReader(input_handle)
            for row in reader:
                hash_value = (row.get("hash") or "").strip().lower()
                record_path = (row.get("path/to/file") or "").strip()
                if not hash_value or not record_path:
                    continue

                shard_index = shard_index_for_hash(hash_value, shard_count)
                writer = _open_shard_writer(
                    shard_dir,
                    "existing-report-shard",
                    shard_index,
                    handles,
                    writers,
                    shard_paths,
                )
                writer.writerow(
                    [normalize_report_ratio(row.get("ratio")), hash_value, record_path]
                )
    finally:
        for handle in handles.values():
            handle.close()

    return shard_paths


def load_cached_hash_ratios(shard_path):
    cached_ratios = {}
    if shard_path is None or not shard_path.exists():
        return cached_ratios

    with shard_path.open("r", newline="", encoding="utf-8") as input_handle:
        reader = csv.DictReader(input_handle)
        for row in reader:
            hash_value = (row.get("hash") or "").strip().lower()
            if not hash_value or hash_value in cached_ratios:
                continue
            cached_ratios[hash_value] = normalize_report_ratio(row.get("ratio"))
    return cached_ratios


def load_existing_row_keys(shard_path):
    row_keys = set()
    if shard_path is None or not shard_path.exists():
        return row_keys

    with shard_path.open("r", newline="", encoding="utf-8") as input_handle:
        reader = csv.DictReader(input_handle)
        for row in reader:
            hash_value = (row.get("hash") or "").strip().lower()
            record_path = (row.get("path/to/file") or "").strip()
            if hash_value and record_path:
                row_keys.add((hash_value, record_path))
    return row_keys


def merge_cumulative_report(report_parts_dir, report_file, existing_report_shards):
    merged_parts_dir = report_parts_dir.parent / "merged-report-shards"
    merged_parts_dir.mkdir(parents=True, exist_ok=True)
    current_report_parts = {
        int(part_path.stem.rsplit("-", 1)[-1]): part_path
        for part_path in report_parts_dir.glob("report-shard-*.csv")
    }

    report_file.parent.mkdir(parents=True, exist_ok=True)
    with report_file.open("w", newline="", encoding="utf-8") as output_handle:
        writer = csv.writer(output_handle)
        writer.writerow(REPORT_COLUMNS)

        for shard_index in sorted(set(existing_report_shards) | set(current_report_parts)):
            seen_rows = set()
            merged_shard_path = merged_parts_dir / f"merged-shard-{shard_index:04d}.csv"
            with merged_shard_path.open("w", newline="", encoding="utf-8") as shard_handle:
                shard_writer = csv.writer(shard_handle)
                shard_writer.writerow(REPORT_COLUMNS)

                for shard_path in (
                    existing_report_shards.get(shard_index),
                    current_report_parts.get(shard_index),
                ):
                    if shard_path is None or not shard_path.exists():
                        continue

                    with shard_path.open("r", newline="", encoding="utf-8") as input_handle:
                        reader = csv.DictReader(input_handle)
                        for row in reader:
                            hash_value = (row.get("hash") or "").strip().lower()
                            record_path = (row.get("path/to/file") or "").strip()
                            if not hash_value or not record_path:
                                continue

                            dedupe_key = (hash_value, record_path)
                            if dedupe_key in seen_rows:
                                continue

                            normalized_ratio = normalize_report_ratio(row.get("ratio"))
                            shard_writer.writerow([normalized_ratio, hash_value, record_path])
                            writer.writerow([normalized_ratio, hash_value, record_path])
                            seen_rows.add(dedupe_key)
