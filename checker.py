import hashlib
import json
import os

TARGET_FILE = r"C:\Users\VEDANTI\Downloads\Operating System Introduction.pptx"

# File to store the hashes
HASH_RECORD_FILE = "hashes.json"

def calculate_hash(filepath):
    """Calculate SHA-256 hash of the file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def save_hash(filepath, hash_value):
    """Save the file hash in a JSON file."""
    if os.path.exists(HASH_RECORD_FILE):
        with open(HASH_RECORD_FILE, "r") as f:
            data = json.load(f)
    else:
        data = {}

    data[filepath] = hash_value

    with open(HASH_RECORD_FILE, "w") as f:
        json.dump(data, f, indent=4)

def check_file(filepath):
    """Check if the file has changed by comparing hashes."""
    new_hash = calculate_hash(filepath)
    if new_hash is None:
        print(f"[!] File not found: {filepath}")
        return

    try:
        with open(HASH_RECORD_FILE, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    old_hash = data.get(filepath)

    if old_hash is None:
        print(f"[+] No previous hash found. Saving hash for: {filepath}")
        save_hash(filepath, new_hash)
    elif new_hash == old_hash:
        print(f"[✓] File is unchanged: {filepath}")
    else:
        print(f"[!!] File has been modified: {filepath}")
        print(f"     Old hash: {old_hash}")
        print(f"     New hash: {new_hash}")

def main():
    print("=== File Integrity Check ===")
    check_file(TARGET_FILE)

if __name__ == "__main__":
    main()
