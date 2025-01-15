import os
import hashlib
import pandas as pd


def hash_file(file_path):
    try:
        # Check file size before processing
        file_size = os.path.getsize(file_path)
        if file_size > 512 * 1024 * 1024:  # 512 MB in bytes
            return file_path, "File too large"

        with open(file_path, "rb") as f:
            md5_hash = hashlib.md5()
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
            return file_path, md5_hash.hexdigest()
    except FileNotFoundError:
        return file_path, "File not found"
    except PermissionError:
        return file_path, "Permission denied"
    except IsADirectoryError:
        return file_path, "Is a directory"
    except OSError as e:
        return file_path, f"OS error: {e}"
    except Exception as e:
        return file_path, f"Unexpected error: {e}"


def hash_files_in_folder(folder_path, output_file):
    try:
        hash_results = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                hash_value = hash_file(file_path)[1]
                hash_results.append((hash_value, file_path))

        # Write results to CSV using pandas for speed
        df = pd.DataFrame(hash_results, columns=["md5", "path/to/file"])
        df.to_csv(output_file, index=False)
        return hash_results

    except PermissionError:
        print(f"Permission error accessing folder: {folder_path}")
        return None
    except FileNotFoundError:
        print(f"Folder not found: {folder_path}")
        return None
    except Exception as e:
        print(f"An error occurred while processing folder: {e}")
        return None


def load_hashes_and_paths_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            hash_db = []
            for line in file:
                parts = line.strip().split(',')
                if len(parts) == 2:  # Giả sử hash và path được phân tách bởi dấu phẩy
                    hash_db.append((parts[0], parts[1]))
                elif len(parts) == 1:  # Chỉ có hash, không có path
                    hash_db.append((parts[0], 'unknown'))
        return hash_db
    except Exception as e:
        print(f"Error reading hash file: {e}")
        return []
