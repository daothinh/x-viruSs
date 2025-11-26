#!/usr/bin/env python
import os
import time
import random
import string
import pandas as pd
import requests
import csv


from dotenv import load_dotenv
from datetime import datetime, timedelta
from utils.md5_hash import hash_files_in_folder, load_hashes_and_paths_from_file

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
REPORT_FILE = os.path.join(BASE_DIR, "data", "report_query.csv")

HASH_DB = os.getenv("HASH_DB")
VT_BASE_URL = os.getenv("URL_SYSINTERNAL_QUERY")
VT_KEYS = os.getenv("SYSINTERNAL_API_KEY")
FOLDER_PATH = os.getenv("FOLDER_TARGET_HASH")
TIME_DELAY = 2
LIMIT_SIZE_QUERY = 100


def random_string(length):
    letters = string.ascii_lowercase + string.digits
    return "".join(random.choice(letters) for i in range(length))


def random_date(start, end):
    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    return start + timedelta(seconds=random_second)


def load_exist_hashes(report_path):
    try:
        df = pd.read_csv(report_path)
        return set(df["hash"])  # Chỉ lấy phần hash để so sánh
    except Exception as e:
        print(f"Error loading existing hashes: {e}")
        return set()


def load_exist_hash_paths(report_path):
    """Load các (hash, file_path) đã có trong report file để tránh duplicate"""
    try:
        df = pd.read_csv(report_path)
        return set(zip(df["hash"], df["path/to/file"]))  # Trả về set các tuple (hash, file_path)
    except Exception as e:
        print(f"Error loading existing hash paths: {e}")
        return set()


def save_vt_detection(report_path, str_hash, detection_ratio, file_path, seen_hashes_in_session=None):
    try:
        # Kiểm tra trùng lặp: nếu (hash, file_path) đã được xử lý trong session này, bỏ qua
        if seen_hashes_in_session is not None:
            hash_path_key = (str_hash, file_path)
            if hash_path_key in seen_hashes_in_session:
                return  # (hash, file_path) đã được lưu trong session này, bỏ qua
            seen_hashes_in_session.add(hash_path_key)
        
        # Kiểm tra xem file có tồn tại không để quyết định việc viết tiêu đề
        file_exists = os.path.isfile(report_path)
        
        # Kiểm tra xem (hash, file_path) đã tồn tại trong file chưa
        if file_exists:
            try:
                df = pd.read_csv(report_path)
                # Kiểm tra duplicate dựa trên cả hash và file_path
                duplicate = df[(df["hash"] == str_hash) & (df["path/to/file"] == file_path)]
                if not duplicate.empty:
                    return  # (hash, file_path) đã tồn tại trong file, bỏ qua
            except Exception:
                pass  # Nếu đọc file lỗi, tiếp tục ghi

        with open(file=report_path, mode="a", newline="", encoding="utf-8") as fs:
            writer = csv.writer(fs)

            # Nếu file không tồn tại, ghi tiêu đề
            if not file_exists:
                writer.writerow(["ratio", "hash", "path/to/file"])

            # Ghi dữ liệu mới vào file
            writer.writerow([detection_ratio, str_hash, file_path])

    except Exception as ex:
        print(ex)


def search_virustotal(batch_hash):
    list_hashes = []
    for hash_string in batch_hash:
        dt1 = datetime.strptime("2015/1/1 1:10 AM", "%Y/%m/%d %I:%M %p")
        dt2 = datetime.strptime("2023/12/1 11:11 PM", "%Y/%m/%d %I:%M %p")
        str1 = random_string(5)
        str2 = random_string(7)
        str3 = random_string(5)
        date_random = random_date(dt1, dt2)
        file_path = f"C:\\{str1}\\{str2}\\{str3}.exe"
        item = {
            "autostart_location": "",
            "autostart_entry": "",
            "hash": hash_string,
            "image_path": file_path,
            "creation_datetime": str(date_random),
        }
        list_hashes.append(item)
    try:
        vt_header_param = {"apikey": VT_KEYS}
        vt_headers = {"User-Agent": "VirusTotal", "Content-type": "application/json"}
        response = requests.post(
            VT_BASE_URL, params=vt_header_param, headers=vt_headers, json=list_hashes
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error - Status code = {response.status_code}")
            # print(batch_hash)
    except Exception as ex:
        print(ex)
    return None


def search_virustotal_batch(hash_db, report_file=REPORT_FILE, seen_hashes_in_session=None):
    try:
        for i in range(0, len(hash_db), LIMIT_SIZE_QUERY):
            batch_hash = hash_db[i : (i + LIMIT_SIZE_QUERY)]
            # hash_db là danh sách của các tuple (hash, file_path)
            # Lọc trùng hash trong batch, giữ lại tuple đầu tiên cho mỗi hash
            seen_hashes = {}
            unique_batch = []
            for item in batch_hash:
                hash_val, file_path = item
                # Bỏ qua (hash, file_path) đã được xử lý trong session này hoặc đã có trong report file
                if seen_hashes_in_session is not None and (hash_val, file_path) in seen_hashes_in_session:
                    continue
                # Lọc trùng hash trong batch để query (chỉ query một lần cho mỗi hash)
                if hash_val not in seen_hashes:
                    seen_hashes[hash_val] = item
                    unique_batch.append(item)
            
            # Nếu không còn hash nào cần query trong batch này, bỏ qua
            if not unique_batch:
                continue
            
            batch_hashes = [item[0] for item in unique_batch]
            response_data = search_virustotal(batch_hashes)
            if response_data is None:
                print(f"Error - Response data in batch hashes is None")
                # print(batch_hashes)
                continue
            time.sleep(TIME_DELAY)
            # Tạo mapping từ hash -> detection_ratio từ response
            hash_to_ratio = {}
            for response_item, (hash_val, _) in zip(response_data["data"], unique_batch):
                detection_ratio = "unknown"
                if response_item["found"] is True:
                    detection_ratio = response_item["detection_ratio"]
                hash_to_ratio[hash_val] = detection_ratio
            
            # Lưu kết quả cho tất cả các file trong batch_hash ban đầu (bao gồm cả các file trùng hash)
            # Hàm save_vt_detection sẽ tự kiểm tra duplicate hash trước khi lưu
            for hash_val, file_path in batch_hash:
                try:
                    detection_ratio = hash_to_ratio.get(hash_val, "unknown")
                    save_vt_detection(report_file, hash_val, detection_ratio, file_path, seen_hashes_in_session)
                    # Định dạng sau khi lưu kết quả: [ratio], [hash], [path/to/file]
                except Exception as ex:
                    print(ex)
    except Exception as ex:
        print(ex)


def sysinternal_vt(input_source):
    if os.path.isdir(input_source):
        hash_db = hash_files_in_folder(input_source, None)
    elif os.path.isfile(input_source):
        hash_db = load_hashes_and_paths_from_file(input_source)
    else:
        print("Invalid input, expected a file_path or folder_path.")
        return

    report_db = load_exist_hashes(REPORT_FILE)
    new_db = [(hash, path) for hash, path in hash_db if hash not in report_db]

    # Tạo set để theo dõi các (hash, file_path) đã xử lý trong session này (tránh trùng lặp giữa các batch)
    seen_hashes_in_session = load_exist_hash_paths(REPORT_FILE)  # Khởi tạo với các (hash, file_path) đã có trong report file

    if len(new_db) > 1:
        search_virustotal_batch(new_db, seen_hashes_in_session=seen_hashes_in_session)
    else:
        print("No new hashes to query")
