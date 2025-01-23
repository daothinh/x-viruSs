import os, requests, json, time, csv
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# configd
api_key = os.getenv("HYBRID_ANALYSIS_API")
directory = os.path.join(BASE_DIR, "samples")
throttle = 20
api_limit = 200
verbose = True

api_base_url = "https://www.hybrid-analysis.com/api/v2/"
user_agent = "Falcon Sandbox"
download_url = "overview/"
search_url = "search/hashes"


def read_csv(file_path):
    hashes = []
    with open(file_path, "r") as csvfile:
        csv_reader = csv.reader(csvfile)
        next(csv_reader)  # Skip header
        for row in csv_reader:
            hashes.append({"hash": row[0], "name": row[1] if len(row) > 1 else None})
    return hashes


def download_sample(download_url, headers, save_directory, sample_hash, filename=None):
    download = requests.get(download_url, headers=headers)
    download.raise_for_status()

    if not os.path.exists(save_directory):
        os.makedirs(save_directory)

    file_name = filename if filename else sample_hash
    temp_path = os.path.join(save_directory, file_name + ".gz")
    final_path = os.path.join(save_directory, sample_hash + ".gz")

    with open(save_directory + "/" + sample_hash + ".gz", "wb") as file:
        file.write(download.content)
    if temp_path != final_path:
        os.rename(temp_path, final_path)


def hybrid_sandbox(input_source):
    headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": user_agent,
        "api-key": api_key,
    }

    download_count = 0

    if os.path.isfile(input_source):
        hashes = read_csv(input_source)
        hash_list = [item["hash"] for item in hashes]
    else:
        hash_list = [input_source]
        hashes = [{"hash": input_source, "name": None}]

    for i in range(0, len(hash_list), api_limit):
        batch = hash_list[i : i + api_limit]
        parameters = {
            f"hashes[{i}]": hash for i, hash in enumerate(batch)
        }

        resp = requests.post(
            api_base_url + search_url, data=parameters, headers=headers
        )
        resp.raise_for_status()
        results = json.loads(resp.text)["result"]

        for result in results:
            if result["verdict"] in ["malicious", "suspicious"]:
                hash_entry = next(
                    (h for h in hashes if h["hash"] == result["md5"]), None
                )
                filename = hash_entry["name"] if hash_entry else None
                if verbose:
                    print(f"[*] Downloading sample - {result['md5']}")
                download_sample(
                    api_base_url + download_url + result["md5"] + "/sample",
                    headers,
                    directory,
                    result["md5"],
                    filename,
                )
                download_count += 1
                time.sleep(throttle)
            if download_count >= api_limit:  # Giới hạn tải xuống theo API
                if verbose:
                    print("[!] Download limit reached")
                break
    print(f"[*] Downloaded {download_count} samples")
