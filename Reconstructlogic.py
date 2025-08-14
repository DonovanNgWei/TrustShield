import struct
import os
import binascii
import hashlib
from zfec import Decoder
from ecdsa import VerifyingKey, NIST256p
from db_operations import insert_log

ZFEC_CHUNK_SIZE = 1024 * 1024

def ReconstructFileWithZFEC(fragment_paths, output_folder=".", progress_callback=None):
    file_groups = {}

    # 1) Parse headers & group shards by file_id
    for path in fragment_paths:
        try:
            with open(path, 'rb') as f:
                if f.read(1) != b'\x02':
                    continue
                fixed = f.read(62)
                file_id_bytes, n, k, file_size, pubkey_bytes, name_len = struct.unpack("!16sHHQ33sB", fixed)
                filename = f.read(name_len)
                signature = f.read(64)
                full_header = b'\x02' + fixed + filename

                vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
                if not vk.verify(signature, full_header, hashfunc=hashlib.sha256):
                    continue

                fid = binascii.hexlify(file_id_bytes).decode()
                grp = file_groups.setdefault(fid, {
                    'n': n, 'k': k,
                    'file_size': file_size,
                    'filename': filename.decode(errors='replace'),
                    'fragments': {}
                })

                idx = int(os.path.basename(path).split('_')[-1].split('.')[0])
                grp['fragments'][idx] = {
                    'path': path,
                    'header_end': f.tell()
                }
        except:
            continue

    # 2) For each file_id, reconstruct if ≥ k shards
    for fid, meta in file_groups.items():
        if len(meta['fragments']) < meta['k']:
            print("Line 49, fail reconstruct")
            #insert_log(fid, 'reconstruct', 'failure',
                       #f"{len(meta['fragments'])}/{meta['k']} shards")
            continue

        total_blocks = (meta['file_size'] + ZFEC_CHUNK_SIZE - 1) // ZFEC_CHUNK_SIZE
        # precompute block sizes & offsets
        block_sizes, shard_sizes, offsets = [], [], [0]
        cum = 0
        for i in range(total_blocks):
            start = i * ZFEC_CHUNK_SIZE
            end   = min(start + ZFEC_CHUNK_SIZE, meta['file_size'])
            orig  = end - start
            pad   = (-orig) % meta['k']
            size  = (orig + pad) // meta['k']
            block_sizes.append(orig)
            shard_sizes.append(size)
            cum += size
            offsets.append(cum)

        decoder = Decoder(meta['k'], meta['n'])
        out_path = os.path.join(output_folder, meta['filename'])
        success = True

        with open(out_path, 'wb') as out:
            for i in range(total_blocks):
                shards = {}
                for idx, info in meta['fragments'].items():
                    if len(shards) >= meta['k']:
                        break
                    with open(info['path'], 'rb') as frag:
                        frag.seek(info['header_end'] + offsets[i])
                        data = frag.read(shard_sizes[i])
                        if len(data) == shard_sizes[i]:
                            shards[idx] = data

                if len(shards) < meta['k']:
                    print("Reconstruct line86")
                    #insert_log(fid, 'reconstruct', 'failure',
                               #f"block {i} only {len(shards)}/{meta['k']} shards")
                    success = False
                    break

                inds = sorted(shards)
                try:
                    decoded = decoder.decode([shards[j] for j in inds], inds)
                    out.write(b''.join(decoded)[:block_sizes[i]])
                except Exception as e:
                    #insert_log(fid, 'reconstruct', 'failure', f"decode error: {e}")
                    success = False
                    break

                if progress_callback:
                    progress_callback(sum(block_sizes[:i+1]), meta['file_size'])

        if success:
            #insert_log(fid, 'reconstruct', 'success')
            print("R..logic.py line104: Reconstruct success")
            return out_path

    return None
