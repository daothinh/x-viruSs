import hashlib
import os
import csv

def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def hash_files_in_directory(directory_path, output_csv):
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["path_file", "md5"])  # Write CSV header

        for root, dirs, files in os.walk(directory_path):
            for file_name in files:
                if file_name.lower().endswith(('.exe', '.dll', '.au3')):
                    file_path = os.path.join(root, file_name)
                    md5_hash = calculate_md5(file_path)
                    writer.writerow([file_path, md5_hash])

# Đường dẫn đến thư mục chứa file .exe và .dll
directory_path = 'path/to/folder'

# Đường dẫn đến file .csv đầu ra
output_csv = 'path/to/output'

# Gọi hàm để băm file và lưu kết quả vào file .csv
hash_files_in_directory(directory_path, output_csv)
