import re
import requests

# Khai báo API key của bạn
API_KEY = 'YOUR API KEY'
BASE_URL = 'https://www.virustotal.com/api/v3/files/'

# Hàm để lấy link từ VirusTotal cho một hash
def get_virustotal_link(hash_value):
    url = BASE_URL + hash_value
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return f'https://www.virustotal.com/gui/file/{hash_value}'  # Link trực tiếp đến hash trên VT
    else:
        return None

# Hàm để parse file và trích xuất hash MD5, SHA-1, SHA-256
def parse_hashes(file_path):
    hashes = []
    patterns = {
        'MD5': re.compile(r'md5:\s*([a-fA-F0-9]{32})\s*'),
        'SHA1': re.compile(r'sha1:\s*([a-fA-F0-9]{40})\s*'),
        'SHA256': re.compile(r'sha256:\s*([a-fA-F0-9]{64})\s*')
    }
    
    with open(file_path, 'r') as f:
        for line in f:
            for hash_type, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    hashes.append((hash_type, match.group(1)))  # Lưu hash theo loại và giá trị
    return hashes

# Hàm chính để xử lý từng hash và lưu link vào file
def process_hashes(file_path, output_file):
    hashes = parse_hashes(file_path)
    with open(output_file, 'w') as out_file:
        for hash_type, hash_value in hashes:
            link = get_virustotal_link(hash_value)
            status = "Founded" if link else "Unkown"
            out_file.write(f'{hash_type}: {hash_value} - {link} {status}\n')
            print(f'{hash_type}: {hash_value}; {status}')

# Chạy chương trình với file input chứa hash và file output để lưu link
input_file = 'path/to/input_file'  # Đường dẫn đến file txt chứa dữ liệu hỗn hợp
output_file = 'path/to/output_file'  # File output để lưu link
process_hashes(input_file, output_file)
