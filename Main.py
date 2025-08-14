import sys
import os
import time
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QStackedLayout, QFrame, QProgressBar,  QMessageBox, QComboBox, QDialog, QInputDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from Encryptionlogic import Encrypt, Decrypt
from Splitlogic import SplitFileWithZFEC 
from Reconstructlogic import ReconstructFileWithZFEC
from auth_helper import register_user, login_user, update_password, reset_password, get_user_email, get_user_id, get_user_public_key, get_user_encrypted_private_key
from subscription_helper import get_user_subscription_info, file_size_checker, get_all_subscription_tiers, format_file_size
from newdb_operations import get_file_owner, get_sharing_enc_session_key, has_file_access
from fragmentCheck import get_file_id_from_any_fragment
from hashFile import hashFile
from verification_email import generate_code, send_verification_email
from recovery_helper import get_user_files, recover_missing_fragments
from sharingPage import SharingPage

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

# Worker thread for encryption and splitting
class EncryptSplitWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)  # (percentage, message)

    def __init__(self, filepath, output_folder, n, k, password, user_identifier, user_subscription_tier, user_max_file_size):
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
            SplitFileWithZFEC(
                self.user_identifier,
                userID,
                self.filepath, 
                self.file_size,
                inputfile_hash,
                self.n, 
                self.k, 
                self.output_folder,
                self.update_split_progress,
                owner_enc_session_key=self._owner_enc_blob
            )
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


class EncryptPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # File selection first
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        file_browse_btn = QPushButton("Browse File")
        file_browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(file_browse_btn)
        layout.addLayout(file_layout)
        layout.addWidget(self._line())

        # RSA key section with password and confirm password
        rsa_section_layout = QVBoxLayout()

        rsa_title = QLabel("Your RSA Key")
        rsa_section_layout.addWidget(rsa_title)

        # Password row
        rsa_password_layout = QHBoxLayout()
        rsa_password_layout.addWidget(QLabel("Password:"))
        self.rsa_input = QLineEdit()
        self.rsa_input.setPlaceholderText("Enter password")
        self.rsa_input.setEchoMode(QLineEdit.Password)
        rsa_password_layout.addWidget(self.rsa_input)
        rsa_section_layout.addLayout(rsa_password_layout)

        # Confirm password row
        rsa_confirm_layout = QHBoxLayout()
        rsa_confirm_layout.addWidget(QLabel("Confirm:  "))
        self.rsa_confirm_input = QLineEdit()
        self.rsa_confirm_input.setPlaceholderText("Confirm password")
        self.rsa_confirm_input.setEchoMode(QLineEdit.Password)
        rsa_confirm_layout.addWidget(self.rsa_confirm_input)
        rsa_section_layout.addLayout(rsa_confirm_layout)

        layout.addLayout(rsa_section_layout)
        layout.addWidget(self._line())

        # Output folder for 
        output_layout = QHBoxLayout()
        
        self.output_folder = QLineEdit()
        self.output_folder.setPlaceholderText("Select output folder for fragments")
        output_browse_btn = QPushButton("Browse Output")
        output_browse_btn.clicked.connect(self.browse_output_folder)
        output_layout.addWidget(QLabel("Fragments Folder:"))
        output_layout.addWidget(self.output_folder)
        output_layout.addWidget(output_browse_btn)
        layout.addLayout(output_layout)

        # n, k inputs
        shard_layout = QHBoxLayout()
        self.n_input = QLineEdit()
        self.k_input = QLineEdit()
        self.n_input.setPlaceholderText("Total shards (n)")
        self.k_input.setPlaceholderText("Required shards (k)")
        shard_layout.addWidget(QLabel("n:"))
        shard_layout.addWidget(self.n_input)
        shard_layout.addWidget(QLabel("k:"))
        shard_layout.addWidget(self.k_input)
        layout.addLayout(shard_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)  # 0-100% range
        self.progress_bar.setVisible(False)
        self.progress_bar.setFormat("%p% - %v/%m")
        layout.addWidget(self.progress_bar)

        # Encrypt & Split Button
        self.go_btn = QPushButton("Encrypt and Split")
        self.go_btn.clicked.connect(self.encrypt_and_split)
        layout.addWidget(self.go_btn, alignment=Qt.AlignCenter)

        # Status Label
        self.status = QLabel("Status:")
        self.status.setFrameStyle(QFrame.Panel | QFrame.Sunken)
        self.status.setFixedHeight(30)
        self.status.setStyleSheet("background-color: #f0f0f0; padding-left: 5px;")
        layout.addWidget(self.status)

        self.setLayout(layout)

    def _line(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def browse_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file:
            self.file_input.setText(file)

    def browse_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output_folder.setText(folder)

    def encrypt_and_split(self):
        try:
            filepath = self.file_input.text()
            n = int(self.n_input.text())
            k = int(self.k_input.text())
            output_folder = self.output_folder.text()
            password = self.rsa_input.text()
            confirm = self.rsa_confirm_input.text()

            if password != confirm:
                self.status.setText("Error: Passwords do not match.")
                self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
                return

            if not os.path.exists(filepath):
                self.status.setText("Error: File does not exist.")
                self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
                return

            if not os.path.isdir(output_folder):
                self.status.setText("Error: Invalid output folder.")
                self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
                return

            # Reset UI
            self.go_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            self.status.setText("Processing...")
            
            # Start worker thread
            user_identifier = self.parent.current_user
            user_subscription_tier = self.parent.user_subscription_tier
            user_max_file_size = self.parent.user_max_file_size

            print("line291" + user_identifier)
            self.worker = EncryptSplitWorker(filepath, output_folder, n, k, password, user_identifier,user_subscription_tier,user_max_file_size)
            self.worker.finished.connect(self.on_encrypt_finished)
            self.worker.error.connect(self.on_encrypt_error)
            self.worker.progress.connect(self.on_progress_update)
            self.worker.start()
            
        except Exception as e:
            self.status.setText(f"Error: {e}")
            self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")

    def on_progress_update(self, percentage, message):
        """Update progress bar and status message"""
        self.progress_bar.setValue(percentage)
        self.status.setText(f"Status: {message}")

    def on_encrypt_finished(self, message):
        self.status.setText(f"Status: {message}")
        self.status.setStyleSheet("color: black; background-color: #f0f0f0; padding-left: 5px;")
        self.go_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

    def on_encrypt_error(self, message):
        self.status.setText(message)
        self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
        self.go_btn.setEnabled(True)
        self.progress_bar.setVisible(False)


class DecryptPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Fragment selection
        frag_layout = QHBoxLayout()
        self.fragment_input = QLineEdit()
        browse_btn = QPushButton("Browse Fragments")
        browse_btn.clicked.connect(self.browse_fragments)
        frag_layout.addWidget(QLabel("Fragments:"))
        frag_layout.addWidget(self.fragment_input)
        frag_layout.addWidget(browse_btn)
        layout.addLayout(frag_layout)

        # Output location
        out_layout = QHBoxLayout()
        self.output_folder = QLineEdit()
        self.output_folder.setPlaceholderText("Select output folder for decrypted file")
        out_browse_btn = QPushButton("Browse Output")
        out_browse_btn.clicked.connect(self.browse_output_folder)
        out_layout.addWidget(QLabel("Decrypted File Folder:"))
        out_layout.addWidget(self.output_folder)
        out_layout.addWidget(out_browse_btn)
        layout.addLayout(out_layout)

        # Decryption password
        pass_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Decryption password")
        pass_layout.addWidget(QLabel("Your RSA Password:"))
        pass_layout.addWidget(self.password_input)
        layout.addLayout(pass_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)  # 0-100% range
        self.progress_bar.setVisible(False)
        self.progress_bar.setFormat("%p% - %v/%m")
        layout.addWidget(self.progress_bar)

        self.go_btn = QPushButton("Reconstruct and Decrypt")
        self.go_btn.clicked.connect(self.reconstruct_and_decrypt)
        layout.addWidget(self.go_btn, alignment=Qt.AlignCenter)

        self.status = QLabel("Status:")
        self.status.setFrameStyle(QFrame.Panel | QFrame.Sunken)
        self.status.setFixedHeight(30)
        self.status.setStyleSheet("background-color: #f0f0f0; padding-left: 5px;")
        layout.addWidget(self.status)

        recover_row = QHBoxLayout()
        recover_row.addStretch()
        self.recover_btn = QPushButton("Recover fragments")
        self.recover_btn.setFixedWidth(150)  # small
        self.recover_btn.clicked.connect(self.recover_fragments_flow)
        recover_row.addWidget(self.recover_btn)
        layout.addLayout(recover_row)

        self.setLayout(layout)
        self.selected_fragments = []

    def browse_fragments(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Fragment Files", filter="Fragment Files (*.frag)")
        if files:
            self.selected_fragments = files
            self.fragment_input.setText(", ".join(os.path.basename(f) for f in files))

    def browse_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output_folder.setText(folder)

    def reconstruct_and_decrypt(self):
        try:
            if not self.selected_fragments or not self.password_input.text():
                self.status.setText("Error: Missing fragments or password.")
                self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
                return
                
            output_folder = self.output_folder.text()
            if not os.path.isdir(output_folder):
                self.status.setText("Error: Invalid output folder.")
                self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
                return
                
            # Reset UI
            self.go_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            self.status.setText("Processing...")
            
            # Start worker thread
            user_identifier = self.parent.current_user
            self.worker = DecryptReconstructWorker(self.selected_fragments, output_folder, self.password_input.text(), user_identifier)
            self.worker.finished.connect(self.on_decrypt_finished)
            self.worker.error.connect(self.on_decrypt_error)
            self.worker.progress.connect(self.on_progress_update)
            self.worker.start()
            
        except Exception as e:
            self.status.setText(f"Error: {e}")
            self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
            self.go_btn.setEnabled(True)
            self.progress_bar.setVisible(False)

    def on_progress_update(self, percentage, message):
        """Update progress bar and status message"""
        self.progress_bar.setValue(percentage)
        self.status.setText(f"Status: {message}")

    def on_decrypt_finished(self, message):
        self.status.setText(f"Status: {message}")
        self.status.setStyleSheet("color: black; background-color: #f0f0f0; padding-left: 5px;")
        self.go_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

    def on_decrypt_error(self, message):
        self.status.setText(message)
        self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
        self.go_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

    def recover_fragments_flow(self):
        email = self.parent.current_user
        
        if not email:
            QMessageBox.warning(self, "Not logged in", "Please login first.")
            return

        out_dir = QFileDialog.getExistingDirectory(self, "Select folder to copy recovered fragments into")
        if not out_dir:
            return
        
        code = generate_code()
        action = "recover file"
        print(f"The code for {action} is: {code}")
            
        self._email_thread = EmailSender(email, code, action, self)
        self._email_thread.start()

        def resend_code():
                new_code = generate_code()
                # send again
                self._email_thread = EmailSender(email, new_code, action, self)
                self._email_thread.start()
                return new_code
            
        dialog = TwoFADialog(expected_code=code, resend_callback=resend_code, duration_seconds=30)

        if dialog.exec_() != QDialog.Accepted:
            return

        try:
            files = get_user_files(email)
            if not files:
                QMessageBox.information(self, "No files", "No files found for your account.")
                return

            if len(files) == 1:
                idx = 0
            else:
                names = [f'{f["filename"]} (id {f["file_id"]})' for f in files]
                choice, ok = QInputDialog.getItem(self, "Choose file", "Select a file:", names, 0, False)
                if not ok:
                    return
                idx = names.index(choice)

            file_id = files[idx]["file_id"]
            filename = files[idx]["filename"]

            result = recover_missing_fragments(email, file_id, out_dir)
            if result["copied"] == 0 and result["have"] == 0:
                QMessageBox.information(self, "Recovery",
                    "No fragments could be recovered from DB or vault.")
                return
            
            msg = (
                f"Recovered {result['copied']} fragment(s).\n"
                f"Now have {result['have']} of {result['n']} shards (k={result['k']})."
            )
            if result["missing"] > 0:
                msg += f"\nStill missing {result['missing']} fragment(s)."
            QMessageBox.information(self, "Recovery complete", msg)
        except Exception as e:
            QMessageBox.critical(self, "Recovery error", str(e))    
        
class ProfilePage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        layout = QVBoxLayout()

        self.title = QLabel("👤 User Profile")
        layout.addWidget(self.title)

        self.email_label = QLabel("Email: ")
        self.username_label = QLabel("Username: ")
        self.subcription_label = QLabel("Subcription Tier: ")
        self.max_size_label = QLabel("Max file size: ")
        layout.addWidget(self.email_label)
        layout.addWidget(self.username_label)
        layout.addWidget(self.subcription_label)
        layout.addWidget(self.max_size_label)

        self.change_pass_btn = QPushButton("Change Password")
        self.change_pass_btn.clicked.connect(self.show_change_password_dialog)
        layout.addWidget(self.change_pass_btn)

        layout.addStretch()
        self.setLayout(layout)

    def set_user_info(self, email, username):
        self.email_label.setText(f"Email: {email}")
        self.username_label.setText(f"Username: {username}")
        self.subcription_label.setText(f"Subcription Tier: {self.parent.user_subscription_tier}")
        self.max_size_label.setText(f"Max upload size: {format_file_size(self.parent.user_max_file_size)}")

    def show_change_password_dialog(self):
        old_pass, ok1 = QInputDialog.getText(self, "Old Password", "Enter old password:", QLineEdit.Password)
        if not ok1 or not old_pass:
            return
        new_pass, ok2 = QInputDialog.getText(self, "New Password", "Enter new password:", QLineEdit.Password)
        if not ok2 or not new_pass:
            return
        confirm_pass, ok3 = QInputDialog.getText(self, "Confirm Password", "Confirm new password:", QLineEdit.Password)
        if not ok3 or new_pass != confirm_pass:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        # Call update password logic
        success, message = update_password(self.parent.current_user, old_pass, new_pass)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Error", message)

        
class LoginPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        layout = QVBoxLayout()

        self.title = QLabel("🔐 Login to TrustShield")
        layout.addWidget(self.title)

        self.identifier_input = QLineEdit()
        self.identifier_input.setPlaceholderText("Email or Username")
        layout.addWidget(self.identifier_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Password")
        layout.addWidget(self.password_input)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)

        self.register_nav_button = QPushButton("Register")
        self.register_nav_button.clicked.connect(lambda: self.parent.update_nav_visibility(1))
        layout.addWidget(self.register_nav_button)
        
        self.forgot_password_button = QPushButton("Forgot Password?")
        self.forgot_password_button.clicked.connect(self.handle_forgot_password)
        layout.addWidget(self.forgot_password_button)

        self.setLayout(layout)

    def handle_login(self):
        identifier = self.identifier_input.text().strip()
        password = self.password_input.text()

        if not identifier or not password:
            QMessageBox.warning(self, "Login Failed", "No inputs detected.")
            return

        success, message, email, username = login_user(identifier, password)
        if success:
            code = generate_code()
            action = "login"
            print(f"The code for {action} is: {code}")
            

            self._email_thread = EmailSender(email, code, action, self)
            self._email_thread.start()

            def resend_code():
                new_code = generate_code()
                # send again
                self._email_thread = EmailSender(email, new_code, action, self)
                self._email_thread.start()
                return new_code
            
            dialog = TwoFADialog(expected_code=code, resend_callback=resend_code, duration_seconds=30)

            if dialog.exec_() == QDialog.Accepted:
                self.parent.current_user = email
                subcriptionInfo = get_user_subscription_info(identifier)
                if subcriptionInfo:
                    self.parent.user_subscription_tier = subcriptionInfo["tier_name"]
                    self.parent.user_max_file_size = subcriptionInfo["max_file_size"]
                self.parent.profile_page.set_user_info(email, username)
                QMessageBox.information(self, "Success", message)
                self.parent.update_nav_visibility(2)
                
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid email/username or password.")
            self.identifier_input.clear()
            self.password_input.clear()
        
    def handle_forgot_password(self):
        identifier = self.identifier_input.text().strip()
        if not identifier:
            QMessageBox.warning(self, "Input Required", "Please enter your email or username first.")
            return
        
        success, user_email = get_user_email(identifier)
        
        if not success:
            QMessageBox.warning(self, "Error", "User not found.")
            return
        
        code = generate_code()
        action = "reset password"
    
        # Show verification + reset password dialog
        dialog = ResetPasswordDialog(user_email, code)
        self._email_thread = EmailSender(user_email, code, action, self)
        self._email_thread.start()
        dialog.exec_()
        

class TwoFADialog(QDialog):
    def __init__(self, expected_code, resend_callback=None, duration_seconds=30):
        super().__init__()
        self.expected_code = expected_code
        self.resend_callback = resend_callback
        self.total_seconds = duration_seconds
        self.seconds_left = duration_seconds

        self.setWindowTitle("Two-Factor Authentication")
        layout = QVBoxLayout(self)

        self.info_label = QLabel("Enter the verification code sent to your email:")
        layout.addWidget(self.info_label)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter verification code")
        self.input.returnPressed.connect(self.verify)  # press Enter to submit
        layout.addWidget(self.input)

        self.countdown_label = QLabel(self._format_time(self.seconds_left))
        self.countdown_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.countdown_label)

        self.submit_btn = QPushButton("Verify")
        self.submit_btn.clicked.connect(self.verify)
        layout.addWidget(self.submit_btn)

        self.resend_btn = QPushButton("Resend code")
        self.resend_btn.setEnabled(False)  # locked until countdown ends
        self.resend_btn.clicked.connect(self._handle_resend)
        layout.addWidget(self.resend_btn)

        # Timer for countdown
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    def _format_time(self, secs):
        m, s = divmod(secs, 60)
        return f"Resend available in {m:02d}:{s:02d}"

    def _tick(self):
        if self.seconds_left > 0:
            self.seconds_left -= 1
            self.countdown_label.setText(self._format_time(self.seconds_left))
        if self.seconds_left == 0:
            self.timer.stop()
            self.countdown_label.setText("You can resend a new code.")
            self.resend_btn.setEnabled(True)

    def _restart_timer(self):
        self.seconds_left = self.total_seconds
        self.countdown_label.setText(self._format_time(self.seconds_left))
        self.resend_btn.setEnabled(False)
        self.timer.start()

    def _handle_resend(self):
        if not self.resend_callback:
            QMessageBox.information(self, "Resend unavailable",
                                    "Resending is not supported in this flow.")
            return
        try:
            new_code = self.resend_callback()
            self.expected_code = new_code
            QMessageBox.information(self, "Code resent",
                                    "A new verification code has been sent to your email.")
            self._restart_timer()
            self.input.clear()
            self.input.setFocus()
        except Exception as e:
            QMessageBox.warning(self, "Resend failed", f"Could not resend code.\n{e}")

    def verify(self):
        if self.input.text().strip() == self.expected_code:
            if self.timer.isActive():
                self.timer.stop()
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Invalid verification code.")

    # Make sure timer is stopped when the dialog closes
    def closeEvent(self, event):
        if self.timer.isActive():
            self.timer.stop()
        super().closeEvent(event)

'''
class TwoFADialog(QDialog):
    def __init__(self, expected_code):
        
        super().__init__()
        self.expected_code = expected_code
        self.setWindowTitle("Two-Factor Authentication")
        self.setLayout(QVBoxLayout())

        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter verification code")
        self.layout().addWidget(self.input)

        self.submit_btn = QPushButton("Verify")
        self.submit_btn.clicked.connect(self.verify)
        self.layout().addWidget(self.submit_btn)

    def verify(self):
        if self.input.text() == self.expected_code:
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Invalid verification code.")
'''
            
class ResetPasswordDialog(QDialog):
    def __init__(self, email, expected_code):
        super().__init__()
        self.setWindowTitle("Reset Password with 2FA")
        self.email = email
        self.expected_code = expected_code

        layout = QVBoxLayout()

        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter verification code")
        layout.addWidget(QLabel("Verification Code:"))
        layout.addWidget(self.code_input)

        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("New Password:"))
        layout.addWidget(self.new_password)

        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Confirm Password:"))
        layout.addWidget(self.confirm_password)

        self.submit_btn = QPushButton("Reset Password")
        self.submit_btn.clicked.connect(self.reset_password)
        layout.addWidget(self.submit_btn)

        self.setLayout(layout)

    def reset_password(self):
        code = self.code_input.text().strip()
        new_pass = self.new_password.text()
        confirm = self.confirm_password.text()

        if code != self.expected_code:
            QMessageBox.warning(self, "Error", "Incorrect verification code.")
            return

        if not new_pass or not confirm:
            QMessageBox.warning(self, "Error", "Please fill all password fields.")
            return

        if new_pass != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        success, message = reset_password(self.email, new_pass)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Error", message)


class RegisterPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        layout = QVBoxLayout()

        self.title = QLabel("📝 Register for TrustShield")
        layout.addWidget(self.title)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        layout.addWidget(self.email_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Password")
        layout.addWidget(self.password_input)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm Password")
        layout.addWidget(self.confirm_password_input)

        self.RSApassword_input = QLineEdit()
        self.RSApassword_input.setEchoMode(QLineEdit.Password)
        self.RSApassword_input.setPlaceholderText("Enter RSA Password")
        layout.addWidget(self.RSApassword_input)

        self.confirm_RSApassword_input = QLineEdit()
        self.confirm_RSApassword_input.setEchoMode(QLineEdit.Password)
        self.confirm_RSApassword_input.setPlaceholderText("Confirm RSA Password")
        layout.addWidget(self.confirm_RSApassword_input)

        # Subscription tier selection
        self.tier_combo = QComboBox()
        self.tiers = get_all_subscription_tiers()
        for tier in self.tiers:
            name = tier[1]
            description = tier[2]
            self.tier_combo.addItem(f"{name} : {description}", tier[0])
        layout.addWidget(QLabel("Select Subscription Tier:"))
        layout.addWidget(self.tier_combo)

        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.handle_register)
        layout.addWidget(self.register_button)

        self.back_button = QPushButton("Back to Login")
        self.back_button.clicked.connect(lambda: self.parent.update_nav_visibility(0))
        layout.addWidget(self.back_button)

        self.setLayout(layout)

    def handle_register(self):
        email = self.email_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_password_input.text()
        RSApass = self.RSApassword_input.text()
        confirmRSA = self.confirm_RSApassword_input.text()
        subscription_tier_id = self.tier_combo.currentData()

        if not email or not username or not password or not confirm or not subscription_tier_id:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return

        if password != confirm:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return
        
        if RSApass != confirmRSA:
            QMessageBox.warning(self, "RSA Password Mismatch", "RSA Passwords do not match.")
            return

        success, message = register_user(email, username, password, RSApass, subscription_tier_id)
        if success:
            QMessageBox.information(self, "Success", message)
            self.parent.update_nav_visibility(0)  # Go back to login
        else:
            QMessageBox.warning(self, "Registration Failed", message)


class MainWindow(QWidget):
    def update_nav_visibility(self, index):
        self.nav_widget.setVisible(index >= 2)
        self.stack.setCurrentIndex(index)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TrustShield - Secure File Encryptor")
        self.setMinimumSize(800, 500)

        main_layout = QHBoxLayout()
        nav_layout = QVBoxLayout()
        nav_layout.setSpacing(10)

        self.stack = QStackedLayout()
        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")
        sharing_btn = QPushButton("Share")
        profile_btn = QPushButton("Profile")

        self.current_user = None
        self.user_subscription_tier = None
        self.user_max_file_size = None
        

        encrypt_btn.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        decrypt_btn.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        sharing_btn.clicked.connect(lambda: self.stack.setCurrentIndex(4))
        profile_btn.clicked.connect(lambda: self.stack.setCurrentIndex(5))

        for btn in [encrypt_btn, decrypt_btn,sharing_btn, profile_btn]:
            btn.setFixedHeight(40)
            nav_layout.addWidget(btn)

        nav_layout.addStretch()
        self.nav_widget = QWidget()
        self.nav_widget.setLayout(nav_layout)
        self.nav_widget.setFixedWidth(150)
        main_layout.addWidget(self.nav_widget)
        
        self.login_page = LoginPage(self)
        self.register_page = RegisterPage(self)
        self.encrypt_page = EncryptPage(self)
        self.decrypt_page = DecryptPage(self)  
        self.sharing_page = SharingPage(self)
        self.profile_page = ProfilePage(self)       
        
        self.stack.addWidget(self.login_page)      # index 0
        self.stack.addWidget(self.register_page)   # index 1
        self.stack.addWidget(self.encrypt_page)    # index 2
        self.stack.addWidget(self.decrypt_page)    # index 3
        self.stack.addWidget(self.sharing_page)    # index 4
        self.stack.addWidget(self.profile_page)    # index 5

        #main_layout.addWidget(nav_widget)
        stack_container = QWidget()
        stack_container.setLayout(self.stack)
        main_layout.addWidget(stack_container)

        self.update_nav_visibility(0)
        self.setLayout(main_layout)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())