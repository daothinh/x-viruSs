import os
import csv
import hashlib

HASH_CHUNK_SIZE = 1024 * 1024


def hash_file(file_path):
    try:
        # Check file size before processing
        file_size = os.path.getsize(file_path)
        if file_size > 512 * 1024 * 1024:  # 512 MB in bytes
            return file_path, "File too large"

        with open(file_path, "rb") as f:
            md5_hash = hashlib.md5()
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
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


def iter_hashes_in_folder(folder_path):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            hash_value = hash_file(file_path)[1]
            yield hash_value, file_path

def hash_files_in_folder(folder_path, output_file=None):
    try:
        hash_results = []
        output_handle = None
        writer = None

        if output_file:
            output_handle = open(output_file, "w", newline="", encoding="utf-8")
            writer = csv.writer(output_handle)
            writer.writerow(["md5", "path/to/file"])

        try:
            for hash_value, file_path in iter_hashes_in_folder(folder_path):
                hash_results.append((hash_value, file_path))
                if writer is not None:
                    writer.writerow([hash_value, file_path])
        finally:
            if output_handle is not None:
                output_handle.close()

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


def iter_hashes_and_paths_from_file(file_path):
    with open(file_path, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.reader(file)
        for row in reader:
            if not row:
                continue

            if len(row) == 2:
                hash_value = row[0].strip()
                file_path_value = row[1].strip() or "unknown"
            elif len(row) == 1:
                hash_value = row[0].strip()
                file_path_value = "unknown"
            else:
                continue

            if hash_value:
                yield hash_value, file_path_value

def load_hashes_and_paths_from_file(file_path):
    try:
        return list(iter_hashes_and_paths_from_file(file_path))
    except Exception as e:
        print(f"Error reading hash file: {e}")
        return []
