import os
import hashlib
from newdb_operations import get_file_hash


CHUNK_SIZE = 64 * 1024  # 64KB

def hashFile(filename, progress_callback=None):
    """Compute file hash incrementally to handle large files"""
    sha256 = hashlib.sha256()
    file_size = os.path.getsize(filename)
    processed = 0
    with open(filename, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, file_size)
    hash_value = sha256.hexdigest()
    print(f"Original file Hash value: {hash_value}")

    return hash_value


def verifyFileHash(filename, file_id, progress_callback=None):
    
    """Verify file hash"""
    original_hash = get_file_hash(file_id)
    if not original_hash:
        print("The original hash value not found. Skipped")
        return

    sha256 = hashlib.sha256()
    file_size = os.path.getsize(filename)
    processed = 0
    with open(filename, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, file_size)
    current_hash = sha256.hexdigest()
    print(f"\nCurrent hash: {current_hash}")
    
    if current_hash == original_hash:
        print("Hash verification successful.")
        return True
    else:
        print("Hash verification failed, the file is damaged.")
        return False
    