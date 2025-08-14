import os
from db_config import get_connection

def get_all_subscription_tiers():
    
    conn, cursor = get_connection()
    
    if not conn:
        return []
    try:
        cursor.execute("SELECT id, name, description, max_file_size FROM subscription_tiers ORDER BY id ASC")
        result = cursor.fetchall()
        if result: 
            return result
        return []
    finally:
        
        cursor.close()
        conn.close()
    

def get_user_subscription_info(identifier):
    """Retrieve user subscription tier name and max_file_size."""
    conn, cursor = get_connection()
    if not conn:
        return None
    try:
        cursor.execute("""
            SELECT s.name, s.max_file_size
            FROM users u
            JOIN subscription_tiers s ON u.subscription_tier_id = s.id
            WHERE u.email = %s OR u.username = %s
        """, (identifier, identifier))
        result = cursor.fetchone()
        if result:
            tier_name, max_file_size = result
            return {
                "tier_name": tier_name,
                "max_file_size": max_file_size
            }
        return None
    finally:
        cursor.close()
        conn.close()

def file_size_checker(user_max_file_size, file_path, user_subscription_tier):
    max_size = user_max_file_size
    file_size = os.path.getsize(file_path)
    max_size_formated = format_file_size(max_size)
    if file_size > max_size:
        return False, f"Your subcription is {user_subscription_tier} tier, only allows files up to {max_size_formated}. Please upgrade your tier."
    return True, None

def format_file_size(size_in_bytes):
    if size_in_bytes >= 1024 ** 3:
        size = size_in_bytes // (1024 ** 3)
        unit = "GB"
    else:
        size = size_in_bytes // (1024 ** 2)
        unit = "MB"
    return f"{size} {unit}"