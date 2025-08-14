from db_config import get_connection

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
