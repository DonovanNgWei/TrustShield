import struct, binascii

# header layout from Splitlogic/Reconstructlogic:
# magic(1) + [16s file_id][H n][H k][Q file_size][33s pubkey][B name_len] + filename + 64B signature
_HEADER_FIXED_FMT = "!16sHHQ33sB"
_HEADER_FIXED_LEN = struct.calcsize(_HEADER_FIXED_FMT)  # 16+2+2+8+33+1 = 62

def read_file_id_from_fragment(path):
    with open(path, 'rb') as f:
        magic = f.read(1)
        if magic != b'\x02':
            raise ValueError("Bad magic")
        fixed = f.read(_HEADER_FIXED_LEN)
        file_id_bytes, n, k, file_size, pubkey_bytes, name_len = struct.unpack(_HEADER_FIXED_FMT, fixed)
        # We don't need to read filename/signature just to get file_id
        return binascii.hexlify(file_id_bytes).decode()
    
def get_file_id_from_any_fragment(fragment_paths):
    last_error = None
    for p in fragment_paths:
        try:
            return read_file_id_from_fragment(p)
        except Exception as e:
            last_error = e
            continue
    raise ValueError(f"Could not read file_id from provided fragments: {last_error}")
