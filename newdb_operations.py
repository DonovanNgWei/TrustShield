from db_config import get_connection

def insertNewFiles(user_id, file_id, filename, size, file_hash, owner_enc_session_key, required_shards, total_shards):
    conn, cursor = get_connection()
    if not conn: return
    cursor.execute(
        "INSERT INTO newfiles (user_id, file_uuid, filename, size, file_hash, owner_enc_session_key, required_shards, total_shards) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (user_id, file_id, filename, size, file_hash, owner_enc_session_key, required_shards, total_shards)
    )
    conn.commit()
    cursor.close()
    conn.close()

def insert_file(file_id, filename, total_shards, required_shards):
    conn, cursor = get_connection()
    if not conn: return
    cursor.execute(
        "INSERT IGNORE INTO files (file_id, filename, total_shards, required_shards) VALUES (%s, %s, %s, %s)",
        (file_id, filename, total_shards, required_shards)
    )
    conn.commit()
    cursor.close()
    conn.close()

def insert_fragment(file_id, fragment_index, fragment_path):
    conn, cursor = get_connection()
    if not conn: return
    cursor.execute(
        "INSERT INTO fragments (file_id, fragment_index, fragment_path) VALUES (%s, %s, %s)",
        (file_id, fragment_index, fragment_path)
    )
    conn.commit()
    cursor.close()
    conn.close()

def insert_log(file_id, action, status, note=None):
    conn, cursor = get_connection()
    if not conn: return
    cursor.execute(
        "INSERT INTO logs (file_id, action, status, note) VALUES (%s, %s, %s, %s)",
        (file_id, action, status, note)
    )
    conn.commit()
    cursor.close()
    conn.close()

def get_file_idNo(uuid):
    """Retrieve hash for the file."""
    conn, cursor = get_connection()
    if not conn:
        return None
    try:
        cursor.execute("SELECT id FROM newfiles WHERE file_uuid= %s", (uuid,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    finally:
        cursor.close()
        conn.close()

def get_file_hash(uuid):
    """Retrieve hash for the file."""
    conn, cursor = get_connection()
    if not conn:
        return None
    try:
        cursor.execute("SELECT file_hash FROM newfiles WHERE file_uuid= %s", (uuid,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    finally:
        cursor.close()
        conn.close()


def insert_file_share(file_id, owner_id, recipient_id, enc_session_key):
    conn, cursor = get_connection()
    if not conn: return
    cursor.execute("""
        INSERT INTO file_shares (file_id, owner_id, recipient_id, enc_session_key)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE enc_session_key=VALUES(enc_session_key)
    """, (file_id, owner_id, recipient_id, enc_session_key))
    conn.commit(); cursor.close(); conn.close()

def get_sharing_enc_session_key(file_id, recipient_id):
    conn, cursor = get_connection()
    if not conn: return None
    cursor.execute("""
        SELECT enc_session_key FROM file_shares
        WHERE file_id=%s AND recipient_id=%s
    """, (file_id, recipient_id))
    row = cursor.fetchone()
    cursor.close(); conn.close()
    return row[0] if row else None

def get_file_owner(file_id):
    conn, cursor = get_connection()
    if not conn: return None
    cursor.execute("SELECT user_id FROM newfiles WHERE file_uuid=%s", (file_id,))
    row = cursor.fetchone()
    cursor.close(); conn.close()
    return row[0] if row else None

def has_file_access(file_id, user_id):
    owner_id = get_file_owner(file_id)
    if owner_id == user_id:
        return True
    conn, cursor = get_connection()
    if not conn: return False
    cursor.execute("""
        SELECT 1 FROM file_shares WHERE file_id=%s AND recipient_id=%s
    """, (file_id, user_id))
    ok = cursor.fetchone() is not None
    cursor.close(); conn.close()
    return ok


#SHARE
def list_user_files(owner_id):
    conn, cursor = get_connection()
    if not conn: return []
    cursor.execute("""
      SELECT file_uuid, filename
      FROM newfiles
      WHERE user_id=%s
      ORDER BY created_at DESC
    """, (owner_id,))
    rows = cursor.fetchall()
    cursor.close(); conn.close()
    return rows or []

def list_file_shares(file_id):
    conn, cursor = get_connection()
    if not conn: return []
    cursor.execute("""
      SELECT fs.recipient_id, COALESCE(u.email, u.username) AS handle, fs.shared_at
      FROM file_shares fs
      LEFT JOIN users u ON u.id = fs.recipient_id
      WHERE fs.file_id=%s
      ORDER BY fs.shared_at DESC
    """, (file_id,))
    rows = cursor.fetchall()
    cursor.close(); conn.close()
    return rows or []

def get_owner_enc_session_key(file_id):
    conn, cursor = get_connection()
    if not conn: return None
    # You need to have saved this during encryption
    cursor.execute("SELECT owner_enc_session_key FROM newfiles WHERE file_uuid=%s", (file_id,))
    row = cursor.fetchone()
    cursor.close(); conn.close()
    return row[0] if row else None

def revoke_share(file_id, recipient_id):
    conn, cursor = get_connection()
    if not conn: return
    cursor.execute("DELETE FROM file_shares WHERE file_id=%s AND recipient_id=%s", (file_id, recipient_id))
    conn.commit(); cursor.close(); conn.close()


def upsert_fragment(file_id, fragment_index, fragment_path):
    """
    Create or update a fragment row for (file_id, fragment_index) and set its path.
    Safe to call repeatedly. Commits or raises on error.
    """
    
    fileid = get_file_idNo(file_id)
    conn, cursor = get_connection()
    if not conn:
        raise RuntimeError("DB connection failed")

    try:
        # make sure parent exists
        cursor.execute("SELECT 1 FROM newfiles WHERE file_uuid=%s", (file_id,))
        if cursor.fetchone() is None:
            raise ValueError(f"upsert_fragment(): parent file '{file_id}' not found")

        # update if exists, else insert
        cursor.execute(
            "SELECT id FROM fragments WHERE file_id=%s AND fragment_index=%s",
            (fileid, fragment_index)
        )
        row = cursor.fetchone()

        if row:
            cursor.execute(
                "UPDATE fragments SET fragment_path=%s WHERE id=%s",
                (fragment_path, row[0])
            )
        else:
            cursor.execute(
                "INSERT INTO fragments (file_id, fragment_index, fragment_path) VALUES (%s, %s, %s)",
                (fileid, fragment_index, fragment_path)
            )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()



