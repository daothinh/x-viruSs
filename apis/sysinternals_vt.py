#!/usr/bin/env python
import os
import time
import random
import string
import secrets
import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()
base = os.path.dirname(os.path.abspath(__file__))

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HASH_DB = os.getenv("HASH_DB")
REPORT_FILE = os.getenv("REPORT_FILE")
VT_BASE_URL = os.getenv("URL_SYSINTERNAL_QUERY")
VT_KEYS = os.getenv("SYSINTERNAL_API_KEY")


TIME_DELAY = 2
BATCH_SIZE = 100


# def random_vt_keys(keys):
#     return secrets.choice(keys)


def random_string(length):
    letters = string.ascii_lowercase + string.digits
    return "".join(random.choice(letters) for i in range(length))


def random_date(start, end):
    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    return start + timedelta(seconds=random_second)

'''
Content in path

ratio, path/to/file
0.0, 1234567890abcdef
0.0, 1234567890abcdef
0.0, 1234567890abcdef
'''
def load_exist_hashes(path):
    try:
        exist_hashes = []
        with open(path) as file:
            lines = [line.rstrip() for line in file]
        for it in lines:
            exist_hashes.append(it.split(",")[-1])
    except Exception as ex:
        print(ex)
    else:
        return list(set(exist_hashes))


def load_new_hashes(path):
    try:
        with open(path) as file:
            lines = [line.rstrip() for line in file]
    except Exception as ex:
        print(ex)
    else:
        return list(set(lines))


def save_vt_detection(file_path, str_hash, detection_ratio):
    try:
        with open(file=file_path, mode="a+", encoding="utf-8") as fs:
            fs.write(f"{detection_ratio},{str_hash}\n")
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
    except Exception as ex:
        print(ex)
    return None


def search_virustotal_batch(hash_db):
    try:
        for i in range(0, len(hash_db), BATCH_SIZE):
            batch_hash = hash_db[i : i + BATCH_SIZE]
            response_data = search_virustotal(batch_hash)
            if response_data is None:
                print(f"Error - Response data in batch hashes is None")
                print(batch_hash)
                continue
            time.sleep(TIME_DELAY)
            for item in response_data["data"]:
                try:
                    str_hash = item["hash"]
                    detection_ratio = "unknown"
                    file_path = os.path.join(BASE_DIR, REPORT_FILE)
                    if item["found"] is True:
                        detection_ratio = item["detection_ratio"]
                    save_vt_detection(file_path, str_hash, detection_ratio)
                except Exception as ex:
                    print(ex)
    except Exception as ex:
        print(ex)


def main():
    path_file = os.path.join(BASE_DIR, HASH_DB)
    report_file = os.path.join(BASE_DIR, REPORT_FILE)
    hash_db = load_new_hashes(path_file)
    report_db = load_exist_hashes(report_file)
    new_db = list(set(hash_db) - set(report_db))
    search_virustotal_batch(new_db)


if __name__ == "__main__":
    main()
