import uuid, hashlib, struct, os, binascii
from zfec import Encoder
from ecdsa import SigningKey, NIST256p
from ecdsa.util import sigencode_string
from newdb_operations import insertNewFiles, get_file_idNo,insert_log, insert_fragment
from vault_helper import backup_fragment, record_file_in_manifest
ZFEC_CHUNK_SIZE = 1024 * 1024
MAX_FILENAME_LEN = 255

def read_file_blocks(filename, block_size):
    with open(filename, 'rb') as f:
        while True:
            b = f.read(block_size)
            if not b: break
            yield b

def wipe_file(filename):
    try:
        size = os.path.getsize(filename)
        with open(filename, 'wb') as f:
            f.write(os.urandom(size))
        os.remove(filename)
    except Exception:
        pass

def SplitFileWithZFEC(owner, user_id, filename, size, file_hash, n, k, output_folder="shards", 
                      progress_callback=None, owner_enc_session_key = None, do_backup = False):

    if k > n:
        raise ValueError("k must be <= n")
    if n > 65535 or k > 65535:
        raise ValueError("n and k must be <= 65535")

    file_id = uuid.uuid4().hex
    original_filename = os.path.basename(filename)[:MAX_FILENAME_LEN]
    file_size = os.path.getsize(filename) #Encrypted file's file size
    print("What wrong")
    insertNewFiles(user_id, file_id, original_filename, size, file_hash, owner_enc_session_key, k, n)
    fileid = get_file_idNo(file_id)
    print(owner)
    
    if do_backup:
        record_file_in_manifest(owner, file_id, original_filename, n, k)
    #insert_log(file_id, 'split', 'started', f"size={file_size}")
    print("What wrong1")
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.verifying_key
    pubkey_bytes = public_key.to_string("compressed")
    header = struct.pack("!B16sHHQ33sB", 2, binascii.unhexlify(file_id), n, k, file_size, pubkey_bytes, len(original_filename)) + original_filename.encode('utf-8')
    signature = private_key.sign(header, hashfunc=hashlib.sha256, sigencode=sigencode_string)

    os.makedirs(output_folder, exist_ok=True)
    frag_paths = [os.path.join(output_folder, f"{file_id}_{i}.frag") for i in range(n)]
    frag_files = [open(p, "wb") for p in frag_paths]
    for f in frag_files:
        f.write(header + signature)

    encoder = Encoder(k, n)
    for idx, p in enumerate(frag_paths):
        insert_fragment(fileid, idx, frag_paths[idx])

    for block in read_file_blocks(filename, ZFEC_CHUNK_SIZE):
        pad_len = (-len(block)) % k
        block += b"\x00" * pad_len
        shard_size = len(block) // k
        shards = [block[i*shard_size:(i+1)*shard_size] for i in range(k)]

        for idx, shard in enumerate(encoder.encode(shards)):
            frag_files[idx].write(shard)

        if progress_callback:
            processed = sum(len(s) for s in shards)
            progress_callback(processed, file_size)

    for f in frag_files:
        f.close()
    for idx, p in enumerate(frag_paths):
        backup_fragment(owner, file_id, idx, p)


    wipe_file(filename)
    #insert_log(file_id, 'split', 'success', f"{n} fragments created")

    return {'file_id': file_id, 'original_file': original_filename, 'public_key': pubkey_bytes.hex(),

            'total_fragments': n, 'required_fragments': k, 'fragment_paths': frag_paths}
