import re

class HashParser:
    
    HASH_PATTERNS = {
        'md5': re.compile(r'([a-fA-F\d]{32})\s*:\s*(\S+)'),
        'sha1': re.compile(r'([a-fA-F\d]{40})\s*:\s*(\S+)'),
        'sha256': re.compile(r'([a-fA-F\d]{64})\s*:\s*(\S+)')
    }

    def __init__(self, file_path):
        self.file_path = file_path

    def parse_hashes(self):

        hashes = {'md5': [], 'sha1': [], 'sha256': []}

        try:
            with open(self.file_path, 'r') as file:
                for line in file:
                    for hash_type, pattern in self.HASH_PATTERNS.items():
                        match = pattern.search(line)
                        if match:
                            # Lấy value của hash và thêm vào danh sách
                            hashes[hash_type].append(match.group(2))
        except FileNotFoundError:
            print(f"File '{self.file_path}' không tồn tại.")
        except Exception as e:
            print(f"Đã xảy ra lỗi: {e}")

        return hashes
