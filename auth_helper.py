import hashlib
from db_config import get_connection
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def CreateRSAKeys(password):
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
    public_key = key.publickey().exportKey()

    return encrypted_key, public_key

def register_user(email, username, password, RSApass, subscription_tier_id):
    # Normalize inputs (won't change what's stored except trimming/lowercasing email)
    email = (email or "").strip().lower()
    username = (username or "").strip()

    encPass = hash_password(password)
    encryptedRSAKey, RSApublickey = CreateRSAKeys(RSApass)

    conn, cursor = get_connection()
    if not conn:
        return False, "Database connection failed."

    try:
        # 1) Pre-check for duplicates
        cursor.execute(
            "SELECT username, email FROM users WHERE username = %s OR LOWER(email) = %s LIMIT 1",
            (username, email)
        )
        row = cursor.fetchone()
        if row:
            # row can be a tuple (username, email)
            existing_username, existing_email = row[0], row[1].lower() if row[1] else ""
            if existing_username == username and existing_email == email:
                return False, "That username and email are already registered."
            if existing_username == username:
                return False, "Username already registered. Please choose another."
            if existing_email == email:
                return False, "Email already registered. Try logging in instead."

        cursor.execute(
            """
            INSERT INTO users
              (username, password_hash, email, rsa_public_key, rsa_private_key_encrypted, subscription_tier_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (username, encPass, email, RSApublickey, encryptedRSAKey, subscription_tier_id)
        )
        conn.commit()
        return True, "Registration successful."

    except Exception as e:

        err_str = str(e).lower()
        duplicate_hit = ("duplicate entry" in err_str) or ("unique constraint" in err_str) or ("1062" in err_str)

        if duplicate_hit:
            # Try to guess which field collided
            if "for key 'email'" in err_str or "email" in err_str:
                return False, "Email already registered. Try logging in instead."
            if "for key 'username'" in err_str or "username" in err_str:
                return False, "Username already registered. Please choose another."
            # Fallback
            return False, "Account already exists with those details."

        # Other DB errors
        return False, f"Registration failed: {e}"

    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
    
def login_user(identifier, password):
    conn, cursor = get_connection()
    if not conn:
        return False, "Database connection failed.", None, None
    try:
        cursor.execute("SELECT email, username, password_hash FROM users WHERE email=%s OR username=%s", (identifier, identifier))
        result = cursor.fetchone()
        
        if not result:
            return False, "User not found.", None, None
        
        email, username, password_hash = result
        
        if hash_password(password) == password_hash:
            return True, "Login successful.", email, username
        return False, "Invalid credentials.", None, None
    finally:
        cursor.close()
        conn.close()

def update_password(identifier,old_password, new_password):
    conn, cursor = get_connection()
    if not conn:
        return False, "Database connection failed."
    try:
        cursor.execute("SELECT password_hash FROM users WHERE email=%s OR username=%s", (identifier, identifier))
        result = cursor.fetchone()
        if not result:
            return False, "User not found."
        
        old_password_hash = result[0]
        if hash_password(old_password) != old_password_hash:
            return False, "Old password is incorrect."
        
        #Update new password
        new_hash = hash_password(new_password)
        cursor.execute("UPDATE users SET password_hash=%s WHERE email=%s OR username=%s",(new_hash, identifier, identifier))
        conn.commit()
        return True, "Password updated successfully."
    except Exception as e:
        return False, f"Error: {str(e)}"
    finally:
        cursor.close()
        conn.close()

def reset_password(identifier, new_password):
    conn, cursor = get_connection()
    if not conn:
        return False, "Database connection failed."
    try: 
        #Update new password
        new_hash = hash_password(new_password)
        cursor.execute("UPDATE users SET password_hash=%s WHERE email=%s", (new_hash, identifier))
        conn.commit()
        return True, "Password reset successfully."
    except Exception as e:
        return False, f"Error: {str(e)}"
    finally:
        cursor.close()
        conn.close()

def get_user_email(identifier):
    conn, cursor = get_connection()
    if not conn:
        return False, None
    try:
        cursor.execute("SELECT email FROM users WHERE email=%s OR username=%s", (identifier, identifier))
        result = cursor.fetchone()
        if result:
            return True, result[0]
        return False, None #user not found
    except Exception as e:
        return False, None
    finally:
        cursor.close()
        conn.close()

def get_user_id(identifier):
    conn, cursor = get_connection()
    if not conn:
        return None
    try:
        cursor.execute("SELECT id FROM users WHERE email=%s OR username=%s", (identifier, identifier))
        result = cursor.fetchone()
        if result:
            return int(result[0])
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_public_key(identifier):
    """Retrieve RSA public key for the user."""
    conn, cursor = get_connection()
    if not conn:
        return None
    try:
        cursor.execute("SELECT rsa_public_key FROM users WHERE email=%s OR username=%s", (identifier, identifier))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_encrypted_private_key(identifier):
    """Retrieve encrypted private key for the user."""
    conn, cursor = get_connection()
    if not conn:
        return None
    try:
        cursor.execute("SELECT rsa_private_key_encrypted FROM users WHERE email=%s OR username=%s", (identifier, identifier))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    finally:
        cursor.close()
        conn.close()

def is_rsa_passphrase_correct(enc_priv_pem, passphrase) -> bool:
    """Return True if passphrase unlocks the encrypted private key, else False."""
    try:
        if isinstance(enc_priv_pem, str):
            enc_priv_pem = enc_priv_pem.encode("utf-8")
        RSA.import_key(enc_priv_pem, passphrase=passphrase)
        return True
    except ValueError:
        return False
