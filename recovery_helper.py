import os, shutil
from db_config import get_connection
from newdb_operations import upsert_fragment
from newdb_operations import get_file_idNo
from vault_helper import list_files_from_vault, list_fragments_from_vault, load_manifest

def get_user_files(identifier):
    conn, cur = get_connection()
    if not conn:
        return list_files_from_vault(identifier)
    try:
        cur.execute("""
            SELECT f.file_uuid, f.filename
            FROM newfiles f
            JOIN users u ON f.user_id = u.id
            WHERE u.email=%s OR u.username=%s
            ORDER BY f.created_at DESC
        """, (identifier, identifier))
        rows = cur.fetchall()
        if rows:
            return [{"file_id": r[0], "filename": r[1]} for r in rows]
        return list_files_from_vault(identifier)
    finally:
        cur.close(); conn.close()

def recover_missing_fragments(identifier: str, file_id: str, dest_dir: str):
    """
    Recover all missing fragments (none, some, or all) into dest_dir without overlap.
    Sources: DB fragment_path, vault backup. Re-hydrates DB rows via upsert.
    Returns dict with counts + ordered paths and reconstructability.
    """
    os.makedirs(dest_dir, exist_ok=True)

    # --- 1) Get n,k,filename from DB (preferred) or from vault manifest
    filename = None; n = None; k = None
    conn, cur = get_connection()
    try:
        if conn:
            cur.execute("SELECT filename, total_shards, required_shards FROM newfiles WHERE file_uuid=%s", (file_id,))
            row = cur.fetchone()
            if row:
                filename, n, k = row[0], int(row[1]), int(row[2])
    finally:
        if conn:
            cur.close(); conn.close()

    if n is None or k is None:
        manifest = load_manifest(identifier)
        meta = (manifest.get("files", {}) or {}).get(file_id)
        if meta:
            filename = meta.get("filename", file_id)
            n = int(meta.get("n"))
            k = int(meta.get("k"))

    if n is None or k is None:
        return {"copied": 0, "skipped_existing": 0, "missing": None, "have": 0,
                "k": None, "n": None, "paths": [], "reconstructable": False,
                "note": "Could not determine (n,k) for this file_id."}

    # --- 2) Determine what we already have in dest_dir by index (avoid overlap)
    existing = {}
    for name in os.listdir(dest_dir):
        if name.startswith(file_id + "_") and name.endswith(".frag"):
            try:
                idx = int(name.split("_")[-1].split(".")[0])
                existing[idx] = os.path.join(dest_dir, name)
            except Exception:
                pass

    # --- 3) Build source maps: DB → path, vault → path
    fileid= get_file_idNo(file_id)
    db_sources = {}
    conn, cur = get_connection()
    try:
        if conn:
            cur.execute("""
                SELECT fragment_path, fragment_index
                FROM fragments
                WHERE file_id=%s
                ORDER BY fragment_index
            """, (fileid,))
            rows = cur.fetchall() or []
            for p, idx in rows:
                if p and os.path.isfile(p):
                    db_sources[int(idx)] = p
    finally:
        if conn:
            cur.close(); conn.close()

    vault_sources = {idx: p for p, idx in list_fragments_from_vault(identifier, file_id)}

    # --- 4) Copy only missing indices; prefer DB, then vault; upsert DB location
    copied = 0
    skipped = len(existing)
    out_paths = dict(existing)  # idx -> dest path
    for idx in range(n):
        if idx in existing:
            continue
        src = db_sources.get(idx) or vault_sources.get(idx)
        if not src or not os.path.isfile(src):
            continue
        dest = os.path.join(dest_dir, f"{file_id}_{idx}.frag")
        if not os.path.exists(dest):
            shutil.copy2(src, dest)
            copied += 1
            out_paths[idx] = dest
        # Update/insert DB row to reflect new (or confirmed) location
        try:
            upsert_fragment(file_id, idx, dest)
        except Exception:
            pass

    have = len(out_paths)
    reconstructable = (have >= k)
    missing = max(0, n - have)
    ordered_paths = [out_paths[i] for i in sorted(out_paths.keys())]

    return {
        "copied": copied,
        "skipped_existing": skipped,
        "missing": missing,
        "have": have,
        "k": k,
        "n": n,
        "paths": ordered_paths,
        "reconstructable": reconstructable
    }

def copy_fragments_to(fragments, dest_dir, filename_base):
    """
    Legacy helper: copy provided [(path, idx), ...] to dest_dir/<filename_base>_fragments.
    """
    target = os.path.join(dest_dir, f"{filename_base}_fragments")
    os.makedirs(target, exist_ok=True)
    copied, errors = 0, []
    for path, idx in fragments:
        try:
            if not os.path.isfile(path):
                errors.append(f"Missing: {path}")
                continue
            out_name = os.path.basename(path) or f"{filename_base}_{idx}.frag"
            shutil.copy2(path, os.path.join(target, out_name))
            copied += 1
        except Exception as e:
            errors.append(f"{path}: {e}")
    return copied, errors
