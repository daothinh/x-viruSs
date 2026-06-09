#!/usr/bin/env python
import csv
import os
import random
import sqlite3
import string
import time
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

from utils.md5_hash import iter_hashes_and_paths_from_file, iter_hashes_in_folder

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
REPORT_FILE = os.path.join(BASE_DIR, "data", "report_query.csv")
REPORT_COLUMNS = ["ratio", "hash", "path/to/file"]

HASH_DB = os.getenv("HASH_DB")
VT_BASE_URL = os.getenv("URL_SYSINTERNAL_QUERY") or os.getenv("URL_QUERY")
VT_KEYS = os.getenv("SYSINTERNAL_API_KEY")
FOLDER_PATH = os.getenv("FOLDER_TARGET_HASH")


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


TIME_DELAY = _env_float("SYSINTERNAL_QUERY_DELAY", 2)
LIMIT_SIZE_QUERY = max(1, _env_int("SYSINTERNAL_BATCH_SIZE", 100))
REQUEST_TIMEOUT = _env_float("SYSINTERNAL_REQUEST_TIMEOUT", 60)
MAX_RETRIES = max(1, _env_int("SYSINTERNAL_MAX_RETRIES", 3))
PROGRESS_INTERVAL = _env_int("SYSINTERNAL_PROGRESS_INTERVAL", 100000)
CACHE_COMMIT_INTERVAL = max(1, _env_int("SYSINTERNAL_CACHE_COMMIT_INTERVAL", 10000))
PENDING_ROW_LIMIT = max(1, _env_int("SYSINTERNAL_PENDING_ROW_LIMIT", 100000))
REPORT_CACHE_FILE = os.getenv("SYSINTERNAL_REPORT_CACHE")


def default_cache_path(report_path):
    if REPORT_CACHE_FILE:
        return os.path.abspath(REPORT_CACHE_FILE)
    report_dir = os.path.dirname(os.path.abspath(report_path))
    report_name = os.path.basename(report_path)
    return os.path.join(report_dir, f"{report_name}.cache.sqlite3")


def normalize_hash(hash_value):
    return str(hash_value).strip().lower()


def normalize_path(file_path):
    path = str(file_path).strip()
    return path if path else "unknown"


def random_string(length):
    letters = string.ascii_lowercase + string.digits
    return "".join(random.choice(letters) for i in range(length))


def random_date(start, end):
    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    return start + timedelta(seconds=random_second)


class ReportCache:
    def __init__(self, report_path, cache_path=None):
        self.report_path = os.path.abspath(report_path)
        self.cache_path = os.path.abspath(cache_path or default_cache_path(report_path))
        self.pending_db_writes = 0
        cache_dir = os.path.dirname(self.cache_path)
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        self.conn = sqlite3.connect(self.cache_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self._create_schema()
        if not self._is_synced_with_report():
            self.rebuild_from_report()

    def _create_schema(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS results (
                hash TEXT PRIMARY KEY,
                ratio TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS report_rows (
                hash TEXT NOT NULL,
                path TEXT NOT NULL,
                PRIMARY KEY (hash, path)
            ) WITHOUT ROWID
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        self.conn.commit()

    def _report_stat(self):
        if not os.path.exists(self.report_path):
            return {"path": os.path.abspath(self.report_path), "size": "0", "mtime_ns": "0"}

        stat = os.stat(self.report_path)
        return {
            "path": os.path.abspath(self.report_path),
            "size": str(stat.st_size),
            "mtime_ns": str(stat.st_mtime_ns),
        }

    def _meta_value(self, key):
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def _is_synced_with_report(self):
        stat = self._report_stat()
        return all(self._meta_value(key) == value for key, value in stat.items())

    def _mark_synced(self):
        stat = self._report_stat()
        self.conn.executemany(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            stat.items(),
        )
        self.conn.commit()

    def rebuild_from_report(self):
        self.conn.execute("DELETE FROM results")
        self.conn.execute("DELETE FROM report_rows")
        self.conn.execute("DELETE FROM meta")
        self.conn.commit()

        if not os.path.exists(self.report_path) or os.path.getsize(self.report_path) == 0:
            self._mark_synced()
            return

        result_rows = []
        report_rows = []
        with open(self.report_path, "r", newline="", encoding="utf-8-sig") as report_file:
            reader = csv.DictReader(report_file)
            for row in reader:
                hash_value = normalize_hash(row.get("hash", ""))
                file_path = normalize_path(row.get("path/to/file", "unknown"))
                ratio = str(row.get("ratio", "unknown") or "unknown")
                if not hash_value:
                    continue

                result_rows.append((hash_value, ratio))
                report_rows.append((hash_value, file_path))
                if len(result_rows) >= CACHE_COMMIT_INTERVAL:
                    self._insert_cache_rows(result_rows, report_rows)
                    result_rows.clear()
                    report_rows.clear()

        self._insert_cache_rows(result_rows, report_rows)
        self._mark_synced()

    def _insert_cache_rows(self, result_rows, report_rows):
        if result_rows:
            self.conn.executemany(
                "INSERT OR REPLACE INTO results(hash, ratio) VALUES(?, ?)",
                result_rows,
            )
        if report_rows:
            self.conn.executemany(
                "INSERT OR IGNORE INTO report_rows(hash, path) VALUES(?, ?)",
                report_rows,
            )
        self.conn.commit()

    def get_ratio(self, hash_value):
        hash_value = normalize_hash(hash_value)
        if not hash_value:
            return None

        row = self.conn.execute(
            "SELECT ratio FROM results WHERE hash = ?",
            (hash_value,),
        ).fetchone()
        return row[0] if row else None

    def add_result(self, hash_value, ratio):
        hash_value = normalize_hash(hash_value)
        if not hash_value:
            return

        self.conn.execute(
            "INSERT OR REPLACE INTO results(hash, ratio) VALUES(?, ?)",
            (hash_value, str(ratio or "unknown")),
        )
        self.pending_db_writes += 1

    def try_add_report_row(self, hash_value, file_path):
        hash_value = normalize_hash(hash_value)
        file_path = normalize_path(file_path)
        if not hash_value:
            return False

        cursor = self.conn.execute(
            "INSERT OR IGNORE INTO report_rows(hash, path) VALUES(?, ?)",
            (hash_value, file_path),
        )
        self.pending_db_writes += cursor.rowcount
        return cursor.rowcount == 1

    def commit_if_needed(self, force=False):
        if force or self.pending_db_writes >= CACHE_COMMIT_INTERVAL:
            self.conn.commit()
            self.pending_db_writes = 0

    def close(self, mark_synced=False):
        self.commit_if_needed(force=True)
        if mark_synced:
            self._mark_synced()
        self.conn.close()


class ReportWriter:
    def __init__(self, report_path, cache):
        self.report_path = os.path.abspath(report_path)
        self.cache = cache
        self.rows_written = 0
        report_dir = os.path.dirname(self.report_path)
        if report_dir:
            os.makedirs(report_dir, exist_ok=True)
        needs_header = not os.path.exists(self.report_path) or os.path.getsize(self.report_path) == 0
        self.handle = open(self.report_path, "a", newline="", encoding="utf-8")
        self.writer = csv.writer(self.handle)
        if needs_header:
            self.writer.writerow(REPORT_COLUMNS)

    def write_if_new(self, hash_value, ratio, file_path):
        normalized_hash = normalize_hash(hash_value)
        file_path = normalize_path(file_path)
        if not self.cache.try_add_report_row(normalized_hash, file_path):
            return False

        self.writer.writerow([ratio, hash_value, file_path])
        self.rows_written += 1
        if self.rows_written % CACHE_COMMIT_INTERVAL == 0:
            self.handle.flush()
            self.cache.commit_if_needed(force=True)
        return True

    def close(self):
        self.handle.flush()
        self.handle.close()


def load_exist_hashes(report_path):
    try:
        cache = ReportCache(report_path)
        rows = cache.conn.execute("SELECT hash FROM results")
        hashes = {row[0] for row in rows}
        cache.close()
        return hashes
    except Exception as e:
        print(f"Error loading existing hashes: {e}")
        return set()


def load_exist_hash_paths(report_path):
    try:
        cache = ReportCache(report_path)
        rows = cache.conn.execute("SELECT hash, path FROM report_rows")
        hash_paths = {(row[0], row[1]) for row in rows}
        cache.close()
        return hash_paths
    except Exception as e:
        print(f"Error loading existing hash paths: {e}")
        return set()


def save_vt_detection(report_path, str_hash, detection_ratio, file_path, seen_hashes_in_session=None):
    try:
        cache = ReportCache(report_path)
        writer = ReportWriter(report_path, cache)
        cache.add_result(str_hash, detection_ratio)
        writer.write_if_new(str_hash, detection_ratio, file_path)
        writer.close()
        cache.close(mark_synced=True)
    except Exception as ex:
        print(ex)


def build_query_payload(batch_hash):
    list_hashes = []
    dt1 = datetime.strptime("2015/1/1 1:10 AM", "%Y/%m/%d %I:%M %p")
    dt2 = datetime.strptime("2023/12/1 11:11 PM", "%Y/%m/%d %I:%M %p")
    for hash_string in batch_hash:
        str1 = random_string(5)
        str2 = random_string(7)
        str3 = random_string(5)
        date_random = random_date(dt1, dt2)
        file_path = f"C:\\{str1}\\{str2}\\{str3}.exe"
        list_hashes.append(
            {
                "autostart_location": "",
                "autostart_entry": "",
                "hash": hash_string,
                "image_path": file_path,
                "creation_datetime": str(date_random),
            }
        )
    return list_hashes


def search_virustotal(batch_hash, session=None):
    if not VT_BASE_URL or not VT_KEYS:
        print("Missing URL_SYSINTERNAL_QUERY or SYSINTERNAL_API_KEY")
        return None

    http = session if session is not None else requests
    list_hashes = build_query_payload(batch_hash)
    vt_header_param = {"apikey": VT_KEYS}
    vt_headers = {"User-Agent": "VirusTotal", "Content-type": "application/json"}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = http.post(
                VT_BASE_URL,
                params=vt_header_param,
                headers=vt_headers,
                json=list_hashes,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()

            print(f"Error - Status code = {response.status_code}")
            if response.status_code not in (429, 500, 502, 503, 504):
                return None
        except Exception as ex:
            print(ex)

        if attempt < MAX_RETRIES:
            time.sleep(min(TIME_DELAY * attempt, 30))

    return None


def parse_detection_ratios(requested_hashes, response_data):
    ratios = {}
    response_items = response_data.get("data", []) if isinstance(response_data, dict) else []
    for response_item, hash_value in zip(response_items, requested_hashes):
        detection_ratio = "unknown"
        if isinstance(response_item, dict) and response_item.get("found") is True:
            detection_ratio = response_item.get("detection_ratio", "unknown")
        ratios[normalize_hash(hash_value)] = detection_ratio

    for hash_value in requested_hashes:
        ratios.setdefault(normalize_hash(hash_value), "unknown")
    return ratios


def flush_pending_queries(pending, cache, writer, session, stats):
    if not pending:
        return True

    requested_hashes = list(pending.keys())
    response_data = search_virustotal(requested_hashes, session=session)
    if response_data is None:
        print("Error - Response data in batch hashes is None")
        stats["failed"] += len(requested_hashes)
        pending.clear()
        return False

    ratios = parse_detection_ratios(requested_hashes, response_data)
    for normalized_hash, items in pending.items():
        detection_ratio = ratios.get(normalized_hash, "unknown")
        cache.add_result(normalized_hash, detection_ratio)
        for display_hash, file_path in items:
            if writer.write_if_new(display_hash, detection_ratio, file_path):
                stats["written"] += 1

    stats["queried"] += len(requested_hashes)
    pending.clear()
    cache.commit_if_needed(force=True)
    if TIME_DELAY > 0:
        time.sleep(TIME_DELAY)
    return True


def search_virustotal_batch(hash_db, report_file=REPORT_FILE, seen_hashes_in_session=None):
    return process_hash_stream(hash_db, report_file=report_file)


def process_hash_stream(hash_iterable, report_file=REPORT_FILE):
    stats = {
        "total": 0,
        "cached": 0,
        "queued": 0,
        "queried": 0,
        "written": 0,
        "duplicates": 0,
        "failed": 0,
    }
    pending = {}
    pending_paths = {}
    pending_item_count = 0
    cache = ReportCache(report_file)
    writer = ReportWriter(report_file, cache)
    session = requests.Session()

    try:
        for hash_value, file_path in hash_iterable:
            stats["total"] += 1
            normalized_hash = normalize_hash(hash_value)
            file_path = normalize_path(file_path)
            if not normalized_hash:
                continue

            cached_ratio = cache.get_ratio(normalized_hash)
            if cached_ratio is not None:
                stats["cached"] += 1
                if writer.write_if_new(hash_value, cached_ratio, file_path):
                    stats["written"] += 1
                else:
                    stats["duplicates"] += 1
            else:
                if normalized_hash not in pending:
                    pending[normalized_hash] = []
                    pending_paths[normalized_hash] = set()

                if file_path in pending_paths[normalized_hash]:
                    stats["duplicates"] += 1
                else:
                    pending[normalized_hash].append((hash_value, file_path))
                    pending_paths[normalized_hash].add(file_path)
                    pending_item_count += 1
                    stats["queued"] += 1

                if len(pending) >= LIMIT_SIZE_QUERY or pending_item_count >= PENDING_ROW_LIMIT:
                    flush_pending_queries(pending, cache, writer, session, stats)
                    pending_paths.clear()
                    pending_item_count = 0

            if PROGRESS_INTERVAL > 0 and stats["total"] % PROGRESS_INTERVAL == 0:
                print(
                    "Processed {total} rows, queried {queried} hashes, "
                    "cached {cached} rows, wrote {written} rows".format(**stats)
                )

        flush_pending_queries(pending, cache, writer, session, stats)
    except Exception as ex:
        print(ex)
    finally:
        writer.close()
        session.close()
        cache.close(mark_synced=True)

    return stats


def iter_input_hashes(input_source):
    if os.path.isdir(input_source):
        yield from iter_hashes_in_folder(input_source)
    elif os.path.isfile(input_source):
        yield from iter_hashes_and_paths_from_file(input_source)
    else:
        raise ValueError("Invalid input, expected a file_path or folder_path.")


def sysinternal_vt(input_source):
    try:
        hash_iter = iter_input_hashes(input_source)
        stats = process_hash_stream(hash_iter)
    except ValueError as ex:
        print(ex)
        return

    if stats["queried"] == 0 and stats["written"] == 0:
        print("No new hashes to query")
    else:
        print(
            "Done. Processed {total} rows, queried {queried} unique hashes, "
            "reused {cached} cached rows, wrote {written} rows, "
            "skipped {duplicates} duplicates, failed {failed} hashes".format(
                **stats
            )
        )
