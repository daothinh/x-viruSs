import csv
import hashlib
import os
import re
import string


HASH_CHUNK_SIZE = 1024 * 1024
HEX_DIGITS = set(string.hexdigits.lower())
HASH_PATTERN = re.compile(r"(?i)([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})")
HEADER_TOKENS = {
    "hash",
    "md5",
    "sha1",
    "sha256",
    "file",
    "path",
    "path/to/file",
    "filepath",
    "file_path",
    "ratio",
    "detection_ratio",
}


def normalize_hash(value):
    candidate = value.strip().lower()
    if len(candidate) not in {32, 40, 64}:
        return None
    if not set(candidate) <= HEX_DIGITS:
        return None
    return candidate


def hash_file(file_path, chunk_size=HASH_CHUNK_SIZE):
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
    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            csv_fields = next(csv.reader([line]))
            if _is_header_row(csv_fields):
                continue

            record = _extract_hash_record(csv_fields, "unknown")
            if record is None and len(csv_fields) == 1:
                record = _extract_hash_record(line.split(), "unknown")
            if record is not None:
                yield record


def is_probably_hash_list_file(file_path, sample_limit=10):
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
                if _extract_hash_record(csv_fields, "unknown") is not None:
                    matched += 1
                if inspected >= sample_limit:
                    break
    except OSError:
        return False
    return inspected > 0 and inspected == matched


def iter_hashes_in_folder(folder_path):
    yield from iter_directory_hash_records(folder_path)

def hash_files_in_folder(folder_path, output_file=None):
    try:
        hash_results = []
        output_handle = None
        writer = None

        if output_file:
            output_handle = open(output_file, "w", newline="", encoding="utf-8")
            writer = csv.writer(output_handle)
            writer.writerow(["md5", "path/to/file"])

        try:
            for hash_value, file_path in iter_hashes_in_folder(folder_path):
                hash_results.append((hash_value, file_path))
                if writer is not None:
                    writer.writerow([hash_value, file_path])
        finally:
            if output_handle is not None:
                output_handle.close()

        return hash_results

    except PermissionError:
        print(f"Permission error accessing folder: {folder_path}")
        return None
    except FileNotFoundError:
        print(f"Folder not found: {folder_path}")
        return None
    except Exception as e:
        print(f"An error occurred while processing folder: {e}")
        return None


def iter_hashes_and_paths_from_file(file_path):
    yield from iter_hash_records_from_file(file_path)


def load_hashes_and_paths_from_file(file_path):
    try:
        return list(iter_hashes_and_paths_from_file(file_path))
    except Exception as e:
        print(f"Error reading hash file: {e}")
        return []
