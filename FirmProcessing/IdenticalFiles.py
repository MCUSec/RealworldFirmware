import os
import hashlib
import sys

def calculate_hash(file_path):
    with open(file_path, 'rb') as f:
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
    return readable_hash

def traverse_directory(directory, hash_dict):
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            if "firminfo" not in filename:
                file_path = os.path.join(dirpath, filename)
                file_hash = calculate_hash(file_path)
                if file_hash in hash_dict:
                    hash_dict[file_hash].append(file_path)
                else:
                    hash_dict[file_hash] = [file_path]

def compare_folders(folder1, folder2):
    hash_dict = {}
    hash_dict1 = {}
    hash_dict2 = {}
    traverse_directory(folder1, hash_dict)
    traverse_directory(folder2, hash_dict)
    identical_files = [files for files in hash_dict.values() if len(files) > 1]
    return identical_files

def main():
    if len(sys.argv) != 3:
        print("Usage: python compare.py folder1 folder2")
        return
    folder1 = sys.argv[1]
    folder2 = sys.argv[2]
    identical_files = compare_folders(folder1, folder2)
    for files in identical_files:
        for f in files:
            fold1 = False
            fold2 = False
            if folder1 in f:
                fold1 = True
            if folder2 in f:
                fold2 = True
        if fold1 and fold2:
            print("\nIdentical files:", files)

if __name__ == "__main__":
    main()
