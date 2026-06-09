import csv
import hashlib
import os
import re
from pathlib import Path


HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
HEX_DIGITS = set("0123456789abcdef")
HEADER_TOKENS = {"hash", "ratio", "path", "path/to/file", "md5", "sha1", "sha256"}


def normalize_hash(value):
    candidate = value.strip().lower()
    if len(candidate) not in {32, 40, 64}:
        return None
    if not set(candidate) <= HEX_DIGITS:
        return None
    return candidate


def hash_file(file_path, chunk_size=1024 * 1024):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()


def iter_directory_hash_records(folder_path):
    for root, _dirs, files in os.walk(folder_path):
        for file_name in files:
            current_path = os.path.join(root, file_name)
            try:
                yield hash_file(current_path), current_path
            except OSError as exc:
                print(f"Skip unreadable file {current_path}: {exc}")


def _extract_hash_record(fields, default_path):
    cleaned_fields = [field.strip() for field in fields if field and field.strip()]
    for index, field in enumerate(cleaned_fields):
        match = HASH_PATTERN.search(field)
        if not match:
            continue

        hash_value = normalize_hash(match.group(0))
        if not hash_value:
            continue

        path_value = default_path
        for candidate in cleaned_fields[index + 1 :]:
            if normalize_hash(candidate):
                continue
            path_value = candidate
            break

        return hash_value, path_value

    return None


def _is_header_row(fields):
    normalized_fields = [field.strip().lower() for field in fields if field and field.strip()]
    return bool(normalized_fields) and all(field in HEADER_TOKENS for field in normalized_fields)


def iter_hash_records_from_file(file_path):
    source_path = str(Path(file_path).resolve())
    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            csv_fields = next(csv.reader([line]))
            if _is_header_row(csv_fields):
                continue

            record = _extract_hash_record(csv_fields, source_path)
            if record is None and len(csv_fields) == 1:
                record = _extract_hash_record(line.split(), source_path)

            if record is not None:
                yield record


def is_probably_hash_list_file(file_path, sample_limit=5):
    inspected = 0
    matched = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                csv_fields = next(csv.reader([line]))
                if _is_header_row(csv_fields):
                    continue

                inspected += 1
                record = _extract_hash_record(csv_fields, str(Path(file_path).resolve()))
                if record is not None:
                    matched += 1

                if inspected >= sample_limit:
                    break
    except OSError:
        return False

    return inspected > 0 and inspected == matched
