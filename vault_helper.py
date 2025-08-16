import os, json, hashlib, shutil, sys
from datetime import datetime

PEPPER = "TrustShield-keep-it-secret"  # obfuscate user vault folder names

def _default_vault_root():
    if sys.platform.startswith("win"):
        root = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "TrustShield")
        os.makedirs(root, exist_ok=True)
        vault = os.path.join(root, ".vault")
        os.makedirs(vault, exist_ok=True)
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(vault, FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass
        return vault
    home = os.path.expanduser("~")
    vault = os.path.join(home, ".trustshield_vault")
    os.makedirs(vault, exist_ok=True)
    return vault

VAULT_ROOT = os.environ.get("TRUSTSHIELD_VAULT_DIR", _default_vault_root())

def _user_hash(identifier: str) -> str:
    return hashlib.sha256((identifier.strip().lower() + PEPPER).encode()).hexdigest()[:32]

def user_vault_dir(identifier: str) -> str:
    d = os.path.join(VAULT_ROOT, "users", _user_hash(identifier))
    os.makedirs(d, exist_ok=True)
    return d

def file_vault_dir(identifier: str, file_id: str) -> str:
    d = os.path.join(user_vault_dir(identifier), "files", file_id)
    os.makedirs(d, exist_ok=True)
    return d

def manifest_path(identifier: str) -> str:
    return os.path.join(user_vault_dir(identifier), "manifest.json")

def load_manifest(identifier: str) -> dict:
    p = manifest_path(identifier)
    if not os.path.isfile(p):
        return {"files": {}}
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def save_manifest(identifier: str, manifest: dict):
    p = manifest_path(identifier)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

def record_file_in_manifest(identifier: str, file_id: str, filename: str, n: int, k: int):
    m = load_manifest(identifier)
    m.setdefault("files", {})
    m["files"][file_id] = {
        "filename": filename,
        "n": int(n),
        "k": int(k),
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    save_manifest(identifier, m)

def backup_fragment(identifier: str, file_id: str, frag_index: int, src_path: str) -> str:
    dst_dir = file_vault_dir(identifier, file_id)
    dst = os.path.join(dst_dir, f"{file_id}_{frag_index}.frag")
    shutil.copy2(src_path, dst)
    return dst

def list_files_from_vault(identifier: str):
    m = load_manifest(identifier)
    return [{"file_id": fid, "filename": meta.get("filename", fid)} for fid, meta in m.get("files", {}).items()]

def list_fragments_from_vault(identifier: str, file_id: str):
    d = file_vault_dir(identifier, file_id)
    if not os.path.isdir(d):
        return []
    items = []
    for name in os.listdir(d):
        if name.startswith(file_id + "_") and name.endswith(".frag"):
            try:
                idx = int(name.split("_")[-1].split(".")[0])
                items.append((os.path.join(d, name), idx))
            except Exception:
                continue
    items.sort(key=lambda x: x[1])
    return items
