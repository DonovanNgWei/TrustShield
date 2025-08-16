# google_drive_integration.py
import os, json, pathlib, sys, urllib.request, io , re, shutil
from typing import Optional, Tuple, List
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request

# Include userinfo scopes so we can show which Google account is linked
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/drive.file",
]

def _client_config_path() -> str:
    p = os.environ.get("GOOGLE_OAUTH_CLIENT_JSON")
    if p and os.path.isfile(p):
        return p
    here = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(__file__).parent))
    return str(here / "google_client_secret.json")

def _token_path(user_vault_dir: str) -> str:
    os.makedirs(user_vault_dir, exist_ok=True)
    return os.path.join(user_vault_dir, "google_token.json")

def _meta_path(user_vault_dir: str) -> str:
    return os.path.join(user_vault_dir, "google.json")

def _save_meta(user_vault_dir: str, meta: dict):
    with open(_meta_path(user_vault_dir), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

def _load_meta(user_vault_dir: str) -> dict:
    p = _meta_path(user_vault_dir)
    if os.path.isfile(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def _find_child_folder(service, parent_id: str, name: str) -> str | None:
    q = (
        f"mimeType='application/vnd.google-apps.folder' "
        f"and name='{name}' and '{parent_id}' in parents and trashed=false"
    )
    res = service.files().list(q=q, fields="files(id,name)", pageSize=1).execute()
    files = res.get("files", [])
    return files[0]["id"] if files else None

def ensure_trustshield_subfolder(service, file_id: str) -> str:
    """Return the folder ID for TrustShield/<file_id>, creating it if needed."""
    root_id = ensure_trustshield_folder(service)
    child_id = _find_child_folder(service, root_id, file_id)
    if child_id:
        return child_id
    meta = {
        "name": file_id,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [root_id],
    }
    created = service.files().create(body=meta, fields="id").execute()
    return created["id"]

def is_google_connected(user_vault_dir: str) -> bool:
    ok, _, _ = ensure_valid_credentials(user_vault_dir, interactive=False)
    return ok

def get_credentials(user_vault_dir: str) -> Optional[Credentials]:
    token_file = _token_path(user_vault_dir)
    creds = None
    if os.path.exists(token_file):
        try:
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
            if creds and creds.valid:
                return creds
        except Exception:
            creds = None  # fall through to consent flow

    flow = InstalledAppFlow.from_client_secrets_file(_client_config_path(), SCOPES)
    # Request offline access so we get refresh_token
    creds = flow.run_local_server(
        port=0,
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true",
    )
    with open(token_file, "w", encoding="utf-8") as f:
        f.write(creds.to_json())
    return creds

def ensure_valid_credentials(user_vault_dir: str, interactive: bool = False) -> Tuple[bool, Optional[Credentials], str]:
    """
    Try to load credentials; if expired and refresh_token exists, refresh silently.
    If interactive=True and we cannot refresh, re-run OAuth to re-link.
    Returns (ok, creds, reason).
    """
    token_file = _token_path(user_vault_dir)
    if not os.path.isfile(token_file):
        if interactive:
            try:
                creds = get_credentials(user_vault_dir)  # opens browser
                return True, creds, "linked"
            except Exception as e:
                return False, None, f"link_failed: {e}"
        return False, None, "no_token"

    try:
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        if creds and creds.valid:
            return True, creds, "valid"

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())  # silent
                with open(token_file, "w", encoding="utf-8") as f:
                    f.write(creds.to_json())
                return True, creds, "refreshed"
            except Exception as e:
                if interactive:
                    try:
                        creds = get_credentials(user_vault_dir)  # re-consent
                        return True, creds, "relinked"
                    except Exception as e2:
                        return False, None, f"relink_failed: {e2}"
                return False, None, f"refresh_failed: {e}"

        # No refresh token available
        if interactive:
            try:
                creds = get_credentials(user_vault_dir)
                return True, creds, "relinked"
            except Exception as e:
                return False, None, f"relink_failed: {e}"
        return False, None, "no_refresh_token"
    except Exception as e:
        if interactive:
            try:
                os.remove(token_file)
            except Exception:
                pass
            try:
                creds = get_credentials(user_vault_dir)
                return True, creds, "relinked"
            except Exception as e2:
                return False, None, f"relink_failed: {e2}"
        return False, None, f"load_failed: {e}"

def get_google_identity(creds: Credentials) -> Tuple[str, str]:
    """
    Returns (google_email, google_sub). Uses OIDC userinfo.
    """
    req = urllib.request.Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {creds.token}"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return data.get("email", ""), data.get("sub", "")

def build_drive(creds: Credentials):
    return build("drive", "v3", credentials=creds)

def ensure_trustshield_folder(service) -> str:
    q = "mimeType='application/vnd.google-apps.folder' and name='TrustShield' and 'root' in parents and trashed=false"
    res = service.files().list(q=q, fields="files(id,name)", pageSize=1).execute()
    files = res.get("files", [])
    if files:
        return files[0]["id"]
    meta = {"name": "TrustShield", "mimeType": "application/vnd.google-apps.folder", "parents": ["root"]}
    created = service.files().create(body=meta, fields="id").execute()
    return created["id"]

def upload_fragment(service, folder_id: str, local_path: str, drive_name: str = None) -> str:
    drive_name = drive_name or os.path.basename(local_path)
    media = MediaFileUpload(local_path, resumable=True)
    body = {"name": drive_name, "parents": [folder_id]}
    req = service.files().create(body=body, media_body=media, fields="id")
    resp = None
    while resp is None:
        status, resp = req.next_chunk()
    return resp["id"]

def disconnect_google(user_vault_dir: str):
    for p in (_token_path(user_vault_dir), _meta_path(user_vault_dir)):
        if os.path.exists(p):
            os.remove(p)


def upload_many_fragments(service, folder_id: str, frag_paths: list, progress_cb=None):
    ids = []
    total = max(1, len(frag_paths))
    for i, p in enumerate(frag_paths, 1):
        fid = upload_fragment(service, folder_id, p, drive_name=os.path.basename(p))
        ids.append(fid)
        if progress_cb:
            progress_cb(i, total)
    return ids

def upload_many_fragments_to_fileid(service, file_id: str, frag_paths: list, progress_cb=None):
    folder_id = ensure_trustshield_subfolder(service, file_id)
    upload_many_fragments(service, folder_id, frag_paths, progress_cb=progress_cb)





FOLDER_MIME = "application/vnd.google-apps.folder"
_FRAG_NAME_RE = re.compile(r"^([0-9a-f]{32})_(\d+)\.frag$", re.IGNORECASE)

def list_trustshield_subfolders(service):
    """Return list of subfolders under TrustShield: [{'id':..., 'name':...}, ...]."""
    parent_id = ensure_trustshield_folder(service)
    q = f"mimeType='{FOLDER_MIME}' and '{parent_id}' in parents and trashed=false"
    res = service.files().list(q=q, fields="files(id,name)", pageSize=1000).execute()
    return res.get("files", [])

def list_fragments_in_folder(service, folder_id):
    """Return [{'id','name','idx'}] for *.frag in the folder, parsing index from name."""
    q = f"'{folder_id}' in parents and trashed=false"
    res = service.files().list(q=q, fields="files(id,name,mimeType,size)", pageSize=1000).execute()
    out = []
    for f in res.get("files", []):
        m = _FRAG_NAME_RE.match(f.get("name", ""))
        if not m:
            continue
        try:
            idx = int(m.group(2))
        except Exception:
            continue
        out.append({"id": f["id"], "name": f["name"], "idx": idx})
    out.sort(key=lambda x: x["idx"])
    return out

def download_file_to(service, file_id, dest_path, progress_cb=None):
    """Download a Drive file to dest_path (resumable)."""
    req = service.files().get_media(fileId=file_id)
    with open(dest_path, "wb") as fh:
        downloader = MediaIoBaseDownload(fh, req)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            if progress_cb and status:
                # status.progress() is 0..1
                progress_cb(status.progress())

def ensure_and_download_k_fragments(service, file_id_str, dest_dir, k):
    """
    Ensure TrustShield/<file_id_str> exists, list fragments, and download up to 'k' at least
    (or all if fewer). Returns list of local paths.
    """
    folder_id = ensure_trustshield_subfolder(service, file_id_str)
    frags = list_fragments_in_folder(service, folder_id)
    if not frags:
        return []
    os.makedirs(dest_dir, exist_ok=True)
    selected = frags[:max(k, 1)]  # at least 1
    paths = []
    for item in selected:
        local = os.path.join(dest_dir, item["name"])
        download_file_to(service, item["id"], local)
        paths.append(local)
    return paths

def make_folder_link_readable(service, folder_id: str):
    """
    Grant link-read (no login) on the folder so recipients can fetch without OAuth.
    Children inherit this by default.
    """
    perm = {
        "type": "anyone",
        "role": "reader",
        "allowFileDiscovery": False  # link-only, not searchable
    }
    # Ignore if already set; Drive returns 409 in some cases
    try:
        service.permissions().create(fileId=folder_id, body=perm, fields="id").execute()
    except Exception:
        pass

def download_public_drive_file(drive_file_id: str, dest_path: str):
    url = f"https://drive.google.com/uc?export=download&id={drive_file_id}"
    with urllib.request.urlopen(url) as r, open(dest_path, "wb") as f:
        shutil.copyfileobj(r, f)

