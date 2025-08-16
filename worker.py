import os
import sys
import time
import re
import shutil

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer

from Encryptionlogic import Encrypt, Decrypt
from Splitlogic import SplitFileWithZFEC
from Reconstructlogic import ReconstructFileWithZFEC

from auth_helper import (
    get_user_id,
    get_user_public_key,
    get_user_encrypted_private_key,
)
from subscription_helper import (
    file_size_checker,
)
from newdb_operations import (
    get_file_owner,
    get_sharing_enc_session_key,
    has_file_access,
    upsert_drive_fragment,
)
from fragmentCheck import get_file_id_from_any_fragment
from hashFile import hashFile
from verification_email import  send_verification_email
from db_config import get_connection

from google_drive_integration import (
    get_credentials,
    build_drive,
    ensure_trustshield_subfolder,
    ensure_valid_credentials,
    upload_many_fragments,
    make_folder_link_readable,
)
from vault_helper import user_vault_dir


_FRAG_RE = re.compile(r"^([0-9a-f]{32})_(\d+)\.frag$", re.IGNORECASE)

def _order_frag_paths(frag_paths):
    """Sort by fragment index parsed from filename."""
    def key(p):
        m = _FRAG_RE.match(os.path.basename(p))
        return int(m.group(2)) if m else 0
    return sorted(frag_paths, key=key)

def _split_evenly_two(frag_paths):
    """Return (to_cloud, to_local) with first half to cloud, rest local."""
    ordered = _order_frag_paths(frag_paths)
    mid = (len(ordered) + 1) // 2  # cloud gets ceil(n/2) when odd
    return ordered[:mid], ordered[mid:]

def _split_evenly_three(frag_paths, use_cloud, use_local1, use_local2,
                        local1_path, local2_path, distribution_plan=None):
    """
    Return (to_cloud, to_local1, to_local2) lists by slicing the ordered fragments.
    If distribution_plan is provided (list of dicts with keys: kind, path, count),
    we honor it; otherwise we compute an even split across the enabled destinations.
    """
    ordered = _order_frag_paths(frag_paths)
    n = len(ordered)

    # If a distribution plan was provided, convert it into a sequence of (label, count)
    if distribution_plan:
        seq = []
        for d in distribution_plan:
            if d.get("kind") == "drive":
                seq.append(("cloud", int(d.get("count", 0))))
            elif d.get("kind") == "local":
                # Distinguish local1 vs local2 by target path
                path = d.get("path") or ""
                label = "local2" if local2_path and os.path.abspath(path) == os.path.abspath(local2_path) else "local1"
                seq.append((label, int(d.get("count", 0))))
        # Normalize counts to not exceed n
        total = sum(c for _, c in seq)
        if total > n:
            # Trim excess from the end
            overflow = total - n
            for i in reversed(range(len(seq))):
                take = min(seq[i][1], overflow)
                seq[i] = (seq[i][0], seq[i][1] - take)
                overflow -= take
                if overflow <= 0:
                    break
    else:
        # Build destination list in stable order: cloud, local1, local2 (only if enabled)
        dests = []
        if use_cloud:
            dests.append("cloud")
        if use_local1:
            dests.append("local1")
        if use_local2:
            dests.append("local2")
        m = max(1, len(dests))
        base = n // m
        rem = n % m
        seq = [(dests[i], base + (1 if i < rem else 0)) for i in range(m)]

    # Slice ordered list according to seq
    pos = 0
    to_cloud, to_local1, to_local2 = [], [], []
    for label, count in seq:
        part = ordered[pos:pos + count]
        pos += count
        if label == "cloud":
            to_cloud.extend(part)
        elif label == "local1":
            to_local1.extend(part)
        elif label == "local2":
            to_local2.extend(part)

    # Any leftovers (due to rounding) go to local1 by default
    if pos < n:
        to_local1.extend(ordered[pos:])

    return to_cloud, to_local1, to_local2

def _parse_index(path):
    m = _FRAG_RE.match(os.path.basename(path))
    return int(m.group(2)) if m else None

def _upload_to_drive(owner_email, file_id, frag_paths, progress_emit=None):
    vault = user_vault_dir(owner_email or "")
    ok, creds, _ = ensure_valid_credentials(vault, interactive=False)
    if not ok or not creds: return False, "Google not connected"

    service = build_drive(creds)
    folder_id = ensure_trustshield_subfolder(service, file_id)

    # Make the whole subfolder link-readable (children inherit)
    try:
        make_folder_link_readable(service, folder_id)
    except Exception:
        pass

    def _cb(done, total):
        if progress_emit:
            pct = 95 + int(4 * done / max(1, total))
            progress_emit(pct, f"Uploading to Google Drive: {done}/{total}")

    # Upload and capture Drive IDs
    drive_ids = upload_many_fragments(service, folder_id, frag_paths, progress_cb=_cb)

    # Persist (file_id, idx) -> drive_file_id
    for path, drive_id in zip(frag_paths, drive_ids):
        idx = _parse_index(path)
        if idx is not None:
            upsert_drive_fragment(file_id, idx, drive_id)

    return True, f"Uploaded to Drive: TrustShield/{file_id}"


def _stash_uploaded_locally(frag_paths, output_folder):
    """
    Move the local copies of shards that were uploaded to a temp 'DriveCopies' folder
    (purely for clarity during the run).
    """
    import shutil, os
    sub = os.path.join(output_folder, "DriveCopies")
    os.makedirs(sub, exist_ok=True)
    moved = 0
    for p in frag_paths:
        try:
            dst = os.path.join(sub, os.path.basename(p))
            if os.path.abspath(p) != os.path.abspath(dst):
                shutil.move(p, dst)
            moved += 1
        except Exception:
            pass
    return moved, sub

def _cleanup_drivecopies(output_folder):
    """Delete the temporary DriveCopies folder after upload."""
    import shutil, os
    sub = os.path.join(output_folder, "DriveCopies")
    if os.path.isdir(sub):
        shutil.rmtree(sub, ignore_errors=True)


'''
# Worker thread for encryption and splitting
class EncryptSplitWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)  # (percentage, message)

    def __init__(self, filepath, 
                 output_folder, n, k, password, user_identifier, 
                 user_subscription_tier, user_max_file_size,
                 store_in_cloud=False, store_in_local = True, 
                 backup_opt_in = False
                ):
        super().__init__()
        self.filepath = filepath
        self.output_folder = output_folder
        self.n = n
        self.k = k
        self.password = password
        self.file_size = os.path.getsize(filepath)
        self.user_identifier = user_identifier
        self.user_subscription_tier = user_subscription_tier
        self.user_max_file_size = user_max_file_size
        self.store_in_cloud = store_in_cloud
        self.store_in_local = store_in_local
        self.backup_opt_in = backup_opt_in
        

    def run(self):
        try:
            # Load RSA keys - 5% progress
            self.progress.emit(5, "Loading RSA key...")
            public_key = get_user_public_key(self.user_identifier)
            userID = get_user_id(self.user_identifier)
            file_size_check, error_message = file_size_checker(self.user_max_file_size,self.filepath,self.user_subscription_tier)
            print("line38:")
            print(userID)
            print("IN Wnc Worker")
            print(self.user_subscription_tier)
            print(self.user_max_file_size)
            inputfile_hash = hashFile(self.filepath)
            print("TEST HASH:" + inputfile_hash)
            
            if not public_key:
                self.error.emit("User public key not found.")
                return
            
            if not file_size_check:
                self.error.emit(error_message)
                return
            
            # 1) Encrypt and capture the owner_enc_session_key
            self._owner_enc_blob = None
            def stash_owner_enc_blob(enc_blob):
                self._owner_enc_blob = enc_blob
            
            # Encrypt file - 25% progress
            self.progress.emit(25, "Encrypting file...")
            startEncrypt = time.time()
            
            Encrypt(self.filepath, public_key, self.update_encrypt_progress, on_session_key=stash_owner_enc_blob, )
            if not self._owner_enc_blob:
                self.error.emit("Failed to capture owner session key.")
                return
            print("Done Encryption--- %s seconds ---" % (time.time() - startEncrypt))
            
            # Split file - progress from 30% to 95%
            self.progress.emit(30, "Splitting file...")
            startSplit= time.time()
            #SplitFileWithZFEC(user_id, filename, size, file_hash, n, k, output_folder="shards", progress_callback=None)
            print("Where")
            result = SplitFileWithZFEC(
                self.user_identifier,
                userID,
                self.filepath, 
                self.file_size,
                inputfile_hash,
                self.n, 
                self.k, 
                self.output_folder,
                self.update_split_progress,
                owner_enc_session_key=self._owner_enc_blob,
                do_backup=self.backup_opt_in
            )
            
            frag_paths = result.get("fragment_paths", [])
            if not frag_paths:
                self.error.emit("No fragments created.")
                return

            # Decide distribution
            to_cloud, to_local = [], []
            if self.store_in_cloud and self.store_in_local:
                to_cloud, to_local = _split_evenly(frag_paths)
            elif self.store_in_cloud:
                to_cloud, to_local = frag_paths, []
            else:
                to_cloud, to_local = [], frag_paths

            # Upload the cloud set (if any)
            if to_cloud:
                ok, msg = _upload_to_drive(self.user_identifier, result["file_id"], to_cloud, self.progress.emit)
                if not ok:
                    # Fall back: keep everything local
                    self.progress.emit(98, f"{msg}. Keeping all fragments locally.")
                    to_local = frag_paths
                else:
                    # (1) Move uploaded copies into a temp folder…
                    moved, sub = _stash_uploaded_locally(to_cloud, self.output_folder)
                    self.progress.emit(99, f"{msg}. Removed local copies of uploaded shards.")
                    # (2) …then delete that temp folder entirely
                    _cleanup_drivecopies(self.output_folder)

            # Put the local-only shards under a folder named with this file_id
            if self.store_in_local and self.store_in_cloud:
                # organize only-the-local half under <fragments_folder>/<file_id>/
                local_dir = os.path.join(self.output_folder, result["file_id"])
                os.makedirs(local_dir, exist_ok=True)
                for p in to_local:
                    try:
                        dst = os.path.join(local_dir, os.path.basename(p))
                        if os.path.abspath(p) != os.path.abspath(dst):
                            shutil.move(p, dst)
                    except Exception:
                        pass
            print("Done Splitting--- %s seconds ---" % (time.time() - startSplit))
            
            # Finalize - 100% progress
            self.progress.emit(100, "Encryption and splitting complete!")
            self.finished.emit("Encrypted and split into fragments")
            
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")
    
    def update_encrypt_progress(self, current, total):
        """Callback function to update progress during encryption"""
        # Calculate percentage (25-30% range for encryption)
        percentage = 25 + int(5 * current / total)
        self.progress.emit(percentage, f"Encrypting: {current}/{total} bytes")
    
    def update_split_progress(self, current, total):
        """Callback function to update progress during splitting"""
        # Calculate percentage (30-95% range for splitting)
        percentage = 30 + int(65 * current / total)
        self.progress.emit(percentage, f"Splitting: {current}/{total} bytes")

'''

class EncryptSplitWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)  # (percentage, message)

    def __init__(self, filepath,
                 output_folder, n, k, password, user_identifier,
                 user_subscription_tier, user_max_file_size,
                 store_in_cloud=False, store_in_local=True,
                 backup_opt_in=False,
                 # NEW:
                 store_in_local2=False, local_output_folder2="",
                 distribution_plan=None):
        super().__init__()
        self.filepath = filepath
        self.output_folder = output_folder               # Local 1
        self.n = n
        self.k = k
        self.password = password
        self.file_size = os.path.getsize(filepath)
        self.user_identifier = user_identifier
        self.user_subscription_tier = user_subscription_tier
        self.user_max_file_size = user_max_file_size
        self.store_in_cloud = store_in_cloud
        self.store_in_local = store_in_local
        self.backup_opt_in = backup_opt_in

        # NEW fields
        self.store_in_local2 = store_in_local2
        self.local_output_folder2 = local_output_folder2  # Local 2
        self.distribution_plan = distribution_plan

    def run(self):
        try:
            # Load RSA keys - 5% progress
            self.progress.emit(5, "Loading RSA key...")
            public_key = get_user_public_key(self.user_identifier)
            userID = get_user_id(self.user_identifier)
            file_size_check, error_message = file_size_checker(self.user_max_file_size, self.filepath, self.user_subscription_tier)
            inputfile_hash = hashFile(self.filepath)

            if not public_key:
                self.error.emit("User public key not found.")
                return

            if not file_size_check:
                self.error.emit(error_message)
                return

            # 1) Encrypt and capture the owner_enc_session_key
            self._owner_enc_blob = None

            def stash_owner_enc_blob(enc_blob):
                self._owner_enc_blob = enc_blob

            # Encrypt file - 25% progress
            self.progress.emit(25, "Encrypting file...")
            startEncrypt = time.time()
            Encrypt(self.filepath, public_key, self.update_encrypt_progress, on_session_key=stash_owner_enc_blob)
            if not self._owner_enc_blob:
                self.error.emit("Failed to capture owner session key.")
                return

            # Split file - progress from 30% to 95%
            self.progress.emit(30, "Splitting file...")
            startSplit = time.time()

            result = SplitFileWithZFEC(
                self.user_identifier,
                userID,
                self.filepath,
                self.file_size,
                inputfile_hash,
                self.n,
                self.k,
                self.output_folder,              # ZFEC writes to Local 1 first
                self.update_split_progress,
                owner_enc_session_key=self._owner_enc_blob,
                do_backup=self.backup_opt_in
            )

            frag_paths = result.get("fragment_paths", [])
            if not frag_paths:
                self.error.emit("No fragments created.")
                return

            # Decide distribution (supports 1, 2, or 3 destinations)
            use_cloud = bool(self.store_in_cloud)
            use_local1 = bool(self.store_in_local)
            use_local2 = bool(self.store_in_local2 and self.local_output_folder2)

            if use_cloud and use_local1 and not use_local2 and not self.distribution_plan:
                # Back-compat behavior when only Drive + Local 1
                to_cloud, to_local1 = _split_evenly_two(frag_paths)
                to_local2 = []
            else:
                to_cloud, to_local1, to_local2 = _split_evenly_three(
                    frag_paths, use_cloud, use_local1, use_local2,
                    self.output_folder, self.local_output_folder2,
                    distribution_plan=self.distribution_plan
                )

            # Upload the cloud set (if any)
            if to_cloud:
                ok, msg = _upload_to_drive(self.user_identifier, result["file_id"], to_cloud, self.progress.emit)
                if not ok:
                    # Fall back: keep everything locally (send cloud batch to Local 1)
                    self.progress.emit(98, f"{msg}. Keeping all fragments locally.")
                    to_local1 = _order_frag_paths(frag_paths)  # everything local 1
                    to_cloud = []
                else:
                    # (1) Move uploaded copies into a temp folder…
                    _ = _stash_uploaded_locally(to_cloud, self.output_folder)
                    self.progress.emit(99, f"{msg}. Removed local copies of uploaded shards.")
                    # (2) …then delete that temp folder entirely
                    _cleanup_drivecopies(self.output_folder)

            # Organize local shards under <local>/ <file_id> / for both local roots
            file_id = result["file_id"]

            def _move_into(local_root, paths):
                if not paths:
                    return
                local_dir = os.path.join(local_root, file_id)
                os.makedirs(local_dir, exist_ok=True)
                for p in paths:
                    try:
                        dst = os.path.join(local_dir, os.path.basename(p))
                        if os.path.abspath(p) != os.path.abspath(dst):
                            shutil.move(p, dst)
                    except Exception:
                        pass

            if use_local1:
                _move_into(self.output_folder, to_local1)

            if use_local2:
                # Ensure target root exists
                os.makedirs(self.local_output_folder2, exist_ok=True)
                _move_into(self.local_output_folder2, to_local2)

            # If neither local was selected (cloud only), remove any left-over local copies
            if use_cloud and not use_local1 and not use_local2:
                # Nothing to move locally; everything was uploaded, and uploaded copies already removed
                pass

            # Finalize - 100% progress
            self.progress.emit(
                100,
                "Done! "
                f"(cloud: {len(to_cloud)}, local1: {len(to_local1)}, local2: {len(to_local2)})"
            )
            self.finished.emit("Encrypted and split into fragments")

        except Exception as e:
            self.error.emit(f"Error: {str(e)}")

    def update_encrypt_progress(self, current, total):
        """Callback function to update progress during encryption"""
        # Calculate percentage (25-30% range for encryption)
        percentage = 25 + int(5 * current / total) if total else 25
        self.progress.emit(percentage, f"Encrypting: {current}/{total} bytes")

    def update_split_progress(self, current, total):
        """Callback function to update progress during splitting"""
        # Calculate percentage (30-95% range for splitting)
        percentage = 30 + int(65 * current / total) if total else 30
        self.progress.emit(percentage, f"Splitting: {current}/{total} bytes")

# Worker thread for reconstruction and decryption
class DecryptReconstructWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)  # (percentage, message)

    def __init__(self, fragments, output_folder, password, user_identifier):
        super().__init__()
        self.fragments = fragments
        self.output_folder = output_folder
        self.password = password
        self.total_size = self.get_total_fragment_size()
        self.user_identifier = user_identifier

    def get_total_fragment_size(self):
        """Calculate total size of all fragments"""
        return sum(os.path.getsize(f) for f in self.fragments)

    def run(self):
        try:

            #File access check
            file_id = get_file_id_from_any_fragment(self.fragments)
            user_id = get_user_id(self.user_identifier) 

            if not has_file_access(file_id, user_id):
                self.error.emit("You do not have permission to reconstruct this file.")
                return
        
            # Reconstruct file - progress from 0% to 60%
            self.progress.emit(0, "Starting reconstruction...")
            startReconstruct = time.time()
            output = ReconstructFileWithZFEC(
                self.fragments, 
                self.output_folder,
                self.update_reconstruct_progress
            )
            print("Done Reconstruct--- %s seconds ---" % (time.time() - startReconstruct))
            
            
            if not output:
                self.error.emit("Reconstruction failed")
                return
            
            #Check owner or recipient 
            owner_id = get_file_owner(file_id)
            shared_enc_session_key = None

            if owner_id != user_id:
                shared_enc_session_key = get_sharing_enc_session_key(file_id, user_id)
                if not shared_enc_session_key:
                    self.error.emit("No shared key found. Access revoked or not shared.")
                    return
            
            # Decrypt file - progress from 60% to 95%
            self.progress.emit(60, "Decrypting file...")
            startDecrypt = time.time()

            encrypted_private_key = get_user_encrypted_private_key(self.user_identifier)
            if not encrypted_private_key:
                self.error.emit("User private key not found.")
                return
            
            Decrypt(output, encrypted_private_key , self.password, file_id, self.update_decrypt_progress, shared_enc_session_key= shared_enc_session_key)
            print("Done Decrypt--- %s seconds ---" % (time.time() - startDecrypt))
            
            # Finalize - 100% progress
            self.progress.emit(100, "Reconstruction and decryption complete!")
            self.finished.emit(f"Reconstructed and decrypted to {os.path.basename(output)}")
            
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")
    
    def update_reconstruct_progress(self, current, total):
        """Callback function to update progress during reconstruction"""
        # Calculate percentage (0-60% range for reconstruction)
        percentage = int(60 * current / total)
        self.progress.emit(percentage, f"Reconstructing: {current}/{total} bytes")
    
    def update_decrypt_progress(self, current, total):
        """Callback function to update progress during decryption"""
        # Calculate percentage (60-95% range for decryption)
        percentage = 60 + int(35 * current / total)
        self.progress.emit(percentage, f"Decrypting: {current}/{total} bytes")


class EmailSender(QThread):
    def __init__(self, email, code, action, parent=None):
        super().__init__(parent)
        self.email = email
        self.code = code
        self.action = action

    def run(self):
        # this runs in a separate thread
        try:
            send_verification_email(self.email, self.code,self.action)
        except Exception as e:
            # optional: log/emit a signal if you want to show a toast
            print("Email send failed:", e)

    
def _upload_fragments_if_connected(owner_email: str, file_id: str, frag_paths: list, progress_emit=None):
    try:
        vault = user_vault_dir(owner_email or "")
        creds = get_credentials(vault)
        if not creds or not creds.valid:
            return False, "Google not connected"
        service = build_drive(creds)

        # Ensure TrustShield/<file_id> exists
        folder_id = ensure_trustshield_subfolder(service, file_id)

        def _cb(done, total):
            if progress_emit:
                pct = 95 + int(4 * done / max(1, total))
                progress_emit(pct, f"Uploading to Google Drive: {done}/{total}")

        upload_many_fragments(service, folder_id, frag_paths, progress_cb=_cb)
        return True, f"Uploaded to Drive: TrustShield/{file_id}"
    except Exception as e:
        return False, f"Upload failed: {e}"
    
class DeleteFileWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)

    def __init__(self, file_uuid: str, user_email: str, extra_local_paths=None):
        """
        file_uuid: newfiles.file_uuid to delete
        user_email: to locate the user's vault/Drive creds
        extra_local_paths: optional list of *file-scoped* folders to remove, e.g.
           [
             "<local_frag_root>/<file_uuid>",
             "<download_out_dir>/<file_uuid>_fragments"
           ]
        """
        super().__init__()
        self.file_uuid = file_uuid
        self.user_email = user_email or ""
        self.extra_local_paths = list(extra_local_paths or [])

    # ---------------- QThread ----------------

    def run(self):
        try:
            # 1) Google Drive — delete TrustShield/<file_uuid>
            self.progress.emit(10, "Google Drive: locating fragment folder…")
            try:
                ok, creds, _ = ensure_valid_credentials(user_vault_dir(self.user_email), interactive=False)
            except Exception:
                ok, creds = False, None

            if ok and creds:
                try:
                    service = build_drive(creds)
                    trustshield_id = self._find_folder_by_name(service, "TrustShield")
                    if trustshield_id:
                        folder_id = self._find_child_folder_by_name(service, trustshield_id, self.file_uuid)
                        if folder_id:
                            self.progress.emit(20, "Google Drive: deleting fragments…")
                            self._drive_recursive_delete(service, folder_id)
                            self.progress.emit(30, "Google Drive: folder removed.")
                except Exception as e:
                    # Non-fatal: continue with local + DB cleanup
                    self.progress.emit(30, f"Google Drive cleanup skipped: {e}")

            # 2) Local vault/backups — best-effort remove file-scoped dirs
            self.progress.emit(45, "Vault: deleting backup fragments…")
            self._delete_local_vault_items()

            # 3) Database records — shares, drive mapping, then file row
            self.progress.emit(70, "Database: deleting records…")
            self._delete_db_records(self.file_uuid)

            self.progress.emit(100, "Delete complete.")
            self.finished.emit("Deleted fragments from Drive, vault, and DB.")
        except Exception as e:
            self.error.emit(f"Delete failed: {e}")

    # ---------------- Google Drive helpers ----------------

    def _find_folder_by_name(self, service, name: str):
        """Find a folder by name anywhere (first match)."""
        q = ("name = '{name}' and mimeType = 'application/vnd.google-apps.folder' "
             "and trashed = false").format(name=name.replace("'", "\\'"))
        resp = service.files().list(q=q, pageSize=10, fields="files(id,name)").execute()
        files = resp.get("files", [])
        return files[0]["id"] if files else None

    def _find_child_folder_by_name(self, service, parent_id: str, name: str):
        q = ("'{parent}' in parents and name = '{name}' and "
             "mimeType = 'application/vnd.google-apps.folder' and trashed = false"
             ).format(parent=parent_id, name=name.replace("'", "\\'"))
        resp = service.files().list(q=q, pageSize=10, fields="files(id,name)").execute()
        files = resp.get("files", [])
        return files[0]["id"] if files else None

    def _drive_recursive_delete(self, service, folder_id: str):
        """
        Permanently delete all children of folder_id (files & subfolders), then the folder itself.
        Drive v3 files.delete() is permanent (not trash).
        """
        # Delete children first (paged)
        page_token = None
        while True:
            resp = service.files().list(
                q=f"'{folder_id}' in parents and trashed = false",
                spaces="drive",
                pageToken=page_token,
                fields="nextPageToken, files(id, name, mimeType)"
            ).execute()
            for item in resp.get("files", []):
                if item["mimeType"] == "application/vnd.google-apps.folder":
                    # recurse
                    self._drive_recursive_delete(service, item["id"])
                else:
                    try:
                        service.files().delete(fileId=item["id"]).execute()
                    except Exception:
                        pass
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        # Delete the (now empty) folder
        try:
            service.files().delete(fileId=folder_id).execute()
        except Exception:
            pass

    # ---------------- Local vault helpers ----------------

    def _delete_local_vault_items(self):
        """
        Remove file-scoped backup dirs:
         - <vault>/recovery/<file_uuid> (if your app uses this)
         - <vault>/backups/<file_uuid> or <vault>/<file_uuid> (best-effort)
         - any extra paths provided by caller
        Only deletes directories whose basename equals file_uuid OR contains file_uuid.
        """
        candidates = set()

        try:
            vault_root = user_vault_dir(self.user_email)  # you already use this for creds
        except Exception:
            vault_root = None

        if vault_root and os.path.isdir(vault_root):
            # Common subfolders used by apps – adjust if your app uses different names
            for sub in ("recovery", "backups", "vault", ""):
                p = os.path.join(vault_root, sub, self.file_uuid) if sub else os.path.join(vault_root, self.file_uuid)
                if os.path.isdir(p):
                    candidates.add(p)

        # Caller-provided, e.g. <local_frag_root>/<file_uuid>, <out_dir>/<file_uuid>_fragments
        for p in self.extra_local_paths:
            if not p:
                continue
            base = os.path.basename(p.rstrip(os.sep))
            if self.file_uuid in base and os.path.exists(p):
                candidates.add(p)

        # Delete candidates safely
        for p in candidates:
            self._safe_rmtree(p)

    def _safe_rmtree(self, path: str):
        try:
            if path and os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass

    # ---------------- DB helpers ----------------

    def _delete_db_records(self, file_uuid: str):
        """
        Order matters:
          1) file_shares (file_uuid)
          2) drive_fragments (file_uuid)
          3) newfiles (file_uuid)  -> will cascade delete fragments(file_id) if FK ON DELETE CASCADE is set
        """
        conn, cur = get_connection()
        if not conn:
            raise RuntimeError("DB connection failed")

        try:
            conn.autocommit = False
            # shares
            cur.execute("DELETE FROM file_shares WHERE file_id = %s", (file_uuid,))
            # drive fragment mapping
            cur.execute("DELETE FROM drive_fragments WHERE file_id = %s", (file_uuid,))
            # the file row — this also removes fragments via ON DELETE CASCADE
            cur.execute("DELETE FROM newfiles WHERE file_uuid = %s", (file_uuid,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass