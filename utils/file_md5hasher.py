import os
import hashlib

class FileHasher:
    def __init__(self, input_path):
        self.input_path = input_path

    def hash_file(self, file_path):
        md5_hash = hashlib.md5()
        try:
            with open(file_path, 'rb') as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except FileNotFoundError:
            print(f"File '{file_path}' không tồn tại.")
            return None

    def hash_all(self):
        hash_results = []
        if os.path.isfile(self.input_path):
            md5 = self.hash_file(self.input_path)
            if md5:
                hash_results.append({"md5": md5, "path": self.input_path})
        elif os.path.isdir(self.input_path):
            
            for root, _, files in os.walk(self.input_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    md5 = self.hash_file(file_path)
                    if md5:
                        hash_results.append({"md5": md5, "path": file_path})
        else:
            print(f"Đường dẫn '{self.input_path}' không hợp lệ.")

        return hash_results
