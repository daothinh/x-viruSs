import os
import time

import requests
from requests.adapters import HTTPAdapter


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


def build_query_payload(hash_values):
    return [
        {
            "autostart_location": "",
            "autostart_entry": "",
            "hash": hash_value,
            "image_path": f"C:\\vt-query\\{hash_value}.bin",
            "creation_datetime": "2024-01-01 00:00:00",
        }
        for hash_value in hash_values
    ]


def map_detection_ratios(response_data, requested_hashes):
    mapped_ratios = {hash_value: "unknown" for hash_value in requested_hashes}
    if not isinstance(response_data, dict):
        return mapped_ratios

    for item in response_data.get("data", []):
        if not isinstance(item, dict):
            continue

        hash_value = (item.get("hash") or "").lower()
        if hash_value not in mapped_ratios:
            continue
        if item.get("found") is True:
            mapped_ratios[hash_value] = item.get("detection_ratio") or "unknown"
    return mapped_ratios


class SysinternalsVTClient:
    DEFAULT_TIMEOUT = _env_float("SYSINTERNAL_REQUEST_TIMEOUT", 60)
    DEFAULT_MAX_RETRIES = max(1, _env_int("SYSINTERNAL_MAX_RETRIES", 3))
    DEFAULT_BACKOFF_SECONDS = _env_float("SYSINTERNAL_QUERY_DELAY", 2)

    def __init__(
        self,
        base_url=None,
        api_key=None,
        timeout=DEFAULT_TIMEOUT,
        max_retries=DEFAULT_MAX_RETRIES,
        backoff_seconds=DEFAULT_BACKOFF_SECONDS,
    ):
        self.base_url = base_url or os.getenv("URL_SYSINTERNAL_QUERY")
        self.api_key = api_key or os.getenv("SYSINTERNAL_API_KEY")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds

        if not self.base_url or not self.api_key:
            raise ValueError("Missing Sysinternals VT configuration")

        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=32, pool_maxsize=32)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def query_hashes(self, hash_values):
        normalized_hashes = [hash_value.lower() for hash_value in hash_values if hash_value]
        if not normalized_hashes:
            return {}

        payload = build_query_payload(normalized_hashes)
        headers = {"User-Agent": "VirusTotal", "Content-type": "application/json"}
        params = {"apikey": self.api_key}
        last_error = "Unknown VT query failure"

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.session.post(
                    self.base_url,
                    params=params,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                )
                if response.status_code == 200:
                    return map_detection_ratios(response.json(), normalized_hashes)

                if response.status_code in {429, 500, 502, 503, 504}:
                    last_error = f"Retryable VT error: HTTP {response.status_code}"
                else:
                    response.raise_for_status()
            except requests.RequestException as exc:
                last_error = str(exc)

            if attempt < self.max_retries:
                time.sleep(self.backoff_seconds * attempt)

        raise RuntimeError(last_error)

    def close(self):
        self.session.close()
