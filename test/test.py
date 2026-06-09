import csv
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from apis.sysinternals_vt_batch_pipeline import (
    BatchQueryConfig,
    iter_input_records,
    run_batch_query,
)
from apis.sysinternals_vt_http_client import SysinternalsVTClient, map_detection_ratios
from utils.md5_hash import hash_file, is_probably_hash_list_file, iter_hash_records_from_file


class VTRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(content_length))
        requested_hashes = [item["hash"].lower() for item in payload]
        self.server.requested_batches.append(requested_hashes)

        response_rows = []
        for hash_value in reversed(requested_hashes):
            response_rows.append(
                {
                    "hash": hash_value,
                    "found": True,
                    "detection_ratio": f"{int(hash_value[0], 16) + 1}/76",
                }
            )

        response_body = json.dumps({"result": 1, "data": response_rows}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, *_args):
        return


class SysinternalsVTPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), VTRequestHandler)
        cls.server.requested_batches = []
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/query"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.server.requested_batches.clear()

    def tearDown(self):
        self.temp_dir.cleanup()

    def build_client(self):
        return SysinternalsVTClient(
            base_url=self.base_url,
            api_key="test-key",
            timeout=5,
            max_retries=2,
            backoff_seconds=0.01,
        )

    def test_hash_list_file_with_header_is_detected_and_parsed(self):
        hash_list = self.root / "hashes.csv"
        hash_list.write_text(
            "hash,path/to/file\n"
            "44d88612fea8a8f36de82e1278abb02f,C:/samples/a.exe\n"
            "64/76,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,C:/samples/b.exe\n",
            encoding="utf-8",
        )

        self.assertTrue(is_probably_hash_list_file(str(hash_list)))
        self.assertEqual(
            list(iter_hash_records_from_file(str(hash_list))),
            [
                ("44d88612fea8a8f36de82e1278abb02f", "C:/samples/a.exe"),
                ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "C:/samples/b.exe"),
            ],
        )

    def test_binary_file_is_hashed_instead_of_treated_as_hash_list(self):
        binary_file = self.root / "payload.bin"
        binary_file.write_bytes(b"\x00\x01virus\x02\x03")

        self.assertFalse(is_probably_hash_list_file(str(binary_file)))
        self.assertEqual(
            list(iter_input_records(str(binary_file))),
            [(hash_file(str(binary_file)), str(binary_file.resolve()))],
        )

    def test_batch_pipeline_queries_unique_hashes_and_merges_all_rows(self):
        hash_list = self.root / "hashes.csv"
        hash_list.write_text(
            "hash,path/to/file\n"
            "44d88612fea8a8f36de82e1278abb02f,C:/samples/a.exe\n"
            "44d88612fea8a8f36de82e1278abb02f,C:/samples/b.exe\n"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,C:/samples/c.exe\n",
            encoding="utf-8",
        )
        report_file = self.root / "report.csv"
        work_root = self.root / "workdir"
        config = BatchQueryConfig(
            report_file=report_file,
            work_root=work_root,
            batch_size=2,
            worker_count=2,
            shard_count=4,
        )

        summary = run_batch_query([str(hash_list)], config, client_factory=self.build_client)

        with report_file.open("r", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertIsNotNone(summary)
        self.assertEqual(summary["total_records"], 3)
        self.assertEqual(summary["queried_hashes"], 2)
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(len(batch) for batch in self.server.requested_batches), 2)

        ratio_by_path = {row["path/to/file"]: row["ratio"] for row in rows}
        self.assertEqual(ratio_by_path["C:/samples/a.exe"], "5/76")
        self.assertEqual(ratio_by_path["C:/samples/b.exe"], "5/76")
        self.assertEqual(ratio_by_path["C:/samples/c.exe"], "11/76")

    def test_response_mapping_is_hash_keyed_not_position_keyed(self):
        requested_hashes = [
            "44d88612fea8a8f36de82e1278abb02f",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
        response_data = {
            "data": [
                {"hash": requested_hashes[1], "found": True, "detection_ratio": "10/76"},
                {"hash": requested_hashes[0], "found": False, "detection_ratio": "64/76"},
            ]
        }

        self.assertEqual(
            map_detection_ratios(response_data, requested_hashes),
            {
                requested_hashes[0]: "unknown",
                requested_hashes[1]: "10/76",
            },
        )


if __name__ == "__main__":
    unittest.main()
