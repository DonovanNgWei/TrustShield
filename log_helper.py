from db_config import get_connection

def log_file_operation(filename, encoded_name, user, operation, hash_value, status='success',
                       file_extension=None, file_size=None, machine=None, hash_verified=None):
    conn, cursor = get_connection()
    if not conn:
        print("❌ Failed to connect to DB for logging.")
        return

    try:
        cursor.execute("""
            INSERT INTO file_logs 
            (filename, encoded_name, user, operation, hash, status, file_extension, file_size, machine, hash_verified)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (filename, encoded_name, user, operation, hash_value, status,
              file_extension, file_size, machine, hash_verified))
        conn.commit()
    except Exception as e:
        print("❌ Logging to DB failed:", e)
    finally:
        cursor.close()
        conn.close()