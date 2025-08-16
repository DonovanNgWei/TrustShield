from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from hashFile import verifyFileHash
import os
import base64
import binascii

# Set chunk size for streaming operations (64KB)
CHUNK_SIZE = 64 * 1024  # 64KB


def Encrypt(filename, public_key, progress_callback=None, on_session_key=None):
    """Encrypt files using streaming to handle large files"""
    # Generate session key and setup cipher
    #recipient_key = RSA.import_key(open('testFolder/my_rsa_public.pem').read())

    recipient_key = RSA.import_key(public_key)
    session_key = get_random_bytes(16)

    
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    if on_session_key:
        on_session_key(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce

    temp_filename = filename + '.tmp'
    file_size = os.path.getsize(filename)
    processed = 0

    try:
        with open(filename, 'rb') as fin, open(temp_filename, 'wb') as fout:
            # Write headers
            fout.write(enc_session_key)
            fout.write(nonce)
            
            # Stream process file
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = cipher_aes.encrypt(chunk)
                fout.write(encrypted_chunk)
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed, file_size)
            
            # Write authentication tag
            tag = cipher_aes.digest()
            fout.write(tag)
        
        # Replace original file
        os.replace(temp_filename, filename)
        
    except Exception as e:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
        raise e


def Decrypt(filename, encrypted_private_key, password, file_id, progress_callback=None, shared_enc_session_key = None):
    """Decrypt files using streaming to handle large files"""
    code = password
    temp_filename = filename + '.tmp'
    
    try:
        # Get file size for tag positioning
        total_size = os.path.getsize(filename)
        if total_size < 288:  # 256 (RSA) + 16 (nonce) + 16 (tag)
            raise ValueError("File too small to be valid encrypted file")
        
        with open(filename, 'rb') as fin:
            # Read headers
            if shared_enc_session_key is None:
                # Owner path → read enc_session_key from file header
                enc_session_key = fin.read(256)
            else:
                # Recipient path → use enc_session_key from file_shares
                enc_session_key = shared_enc_session_key
                # Skip past the 256 bytes in file header
                fin.seek(256)

            nonce = fin.read(16)
            # Get private key
            private_key = RSA.import_key(
                encrypted_private_key, 
                passphrase=code
            )
            
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            
            # Calculate ciphertext size (excluding headers and tag)
            ciphertext_size = total_size - 256 - 16 - 16
            processed = 0
            
            # Stream process file
            with open(temp_filename, 'wb') as fout:
                while processed < ciphertext_size:
                    read_size = min(CHUNK_SIZE, ciphertext_size - processed)
                    chunk = fin.read(read_size)
                    if not chunk:
                        break
                    plaintext = cipher_aes.decrypt(chunk)
                    fout.write(plaintext)
                    processed += len(chunk)
                    if progress_callback:
                        progress_callback(processed, ciphertext_size)
                
                # Verify authentication tag
                tag = fin.read(16)
                try:
                    cipher_aes.verify(tag)
                except ValueError:
                    raise ValueError("Authentication tag mismatch - file corrupted")
        
        # Replace encrypted file with decrypted
        os.replace(temp_filename, filename)

        # Verify file integrity
        if verifyFileHash(filename, file_id, progress_callback):
            print("Decrypt success!")
        else:
            raise ValueError("Hash verification failed after decryption, the file is damaged.")


    except Exception as e:
        # Clean up temporary files on failure
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
        if "Authentication" in str(e):
            raise Exception("Decryption failed: File may be corrupted") from e
        elif "RSA key format" in str(e) or "decrypt" in str(e).lower():
            raise Exception("Wrong password or corrupted RSA key") from e
        else:
            raise Exception(f"Decryption failed: {str(e)}") from e

def RenameFile(dir, filename):
    filename_bytes = filename.encode('utf-8')
    filename_b64 = base64.b64encode(filename_bytes).decode('utf-8')
    new_filename = filename_b64 + '.TShield'
    os.rename(os.path.join(dir, filename), os.path.join(dir, new_filename))

def ReverseFilename(dir, filename):
    if filename.endswith('.TShield'):
        filename_b64 = filename[:-7]
        try:
            original_bytes = base64.b64decode(filename_b64)
            original_name = original_bytes.decode('utf-8')
            os.rename(os.path.join(dir, filename), os.path.join(dir, original_name))
        except (binascii.Error, UnicodeDecodeError) as e:
            print(f"Fail to decode filename: {e}")
    else:
        print("Invalid encrypt file type.")