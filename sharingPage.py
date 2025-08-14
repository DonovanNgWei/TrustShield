# sharing_page.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QComboBox, QTableWidget, QTableWidgetItem,QInputDialog
)
from PyQt5.QtCore import Qt
from auth_helper import (get_user_id, # (identifier) -> int
                        get_user_public_key,
                        get_user_encrypted_private_key,     # (identifier or id) -> PEM
                        is_rsa_passphrase_correct)
from newdb_operations import (
    list_user_files,        # (owner_id) -> [(file_uuid, filename)]
    list_file_shares,       # (file_id) -> [(recipient_id, recipient_name_or_email, shared_at)]
    get_owner_enc_session_key,  # (file_id) -> bytes (RSA-encrypted AES key for owner)
    insert_file_share,
    revoke_share,
    
)

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class SharingPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.owner_id = None

        layout = QVBoxLayout()
        layout.setSpacing(12)

        # Title
        layout.addWidget(QLabel("🔗 Share Files"))

        # Select file to share
        top = QHBoxLayout()
        top.addWidget(QLabel("Your Files:"))
        self.file_combo = QComboBox()
        top.addWidget(self.file_combo, stretch=1)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_files)
        top.addWidget(refresh_btn)
        layout.addLayout(top)

        # Recipient row
        rec_row = QHBoxLayout()
        rec_row.addWidget(QLabel("Recipient (email/username):"))
        self.recipient_input = QLineEdit()
        rec_row.addWidget(self.recipient_input)
        share_btn = QPushButton("Share")
        share_btn.clicked.connect(self.handle_share)
        rec_row.addWidget(share_btn)
        layout.addLayout(rec_row)

        # Current shares table
        layout.addWidget(QLabel("Current Shares:"))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Recipient", "Shared At", "Actions"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        self.setLayout(layout)

        # Load initial data when page is shown
        self.file_combo.currentIndexChanged.connect(self.refresh_shares)

    def showEvent(self, event):
        super().showEvent(event)
        # Resolve owner id
        if self.parent.current_user:
            self.owner_id = get_user_id(self.parent.current_user)
        self.refresh_files()

    def refresh_files(self):
        self.file_combo.clear()
        if not self.owner_id:
            return
        files = list_user_files(self.owner_id) or []
        # Expect tuples: (file_uuid, filename)
        for fid, fname in files:
            label = f"{fname}  ({fid[:8]}…)"
            self.file_combo.addItem(label, fid)
        self.refresh_shares()

    def current_file_id(self):
        idx = self.file_combo.currentIndex()
        if idx < 0:
            return None
        return self.file_combo.itemData(idx)

    def refresh_shares(self):
        file_id = self.current_file_id()
        self.table.setRowCount(0)
        if not file_id:
            return
        rows = list_file_shares(file_id) or []
        for (recipient_id, recipient_handle, shared_at) in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(recipient_handle or str(recipient_id)))
            self.table.setItem(r, 1, QTableWidgetItem(str(shared_at) if shared_at else ""))

            # Revoke button
            btn = QPushButton("Revoke")
            btn.clicked.connect(lambda _, rid=recipient_id, fid=file_id: self.handle_revoke(fid, rid))
            self.table.setCellWidget(r, 2, btn)

     
    def prompt_rsa_passphrase(self):
        rsa_pass, ok = QInputDialog.getText(
            self,
            "RSA Passphrase Required",
            "Enter your RSA passphrase:",
            QLineEdit.Password
        )
        if ok and rsa_pass.strip():
            return rsa_pass.strip()
        else:
            QMessageBox.warning(self, "Cancelled", "Sharing cancelled: RSA passphrase required.")
            return None

    def handle_share(self):
        file_id = self.current_file_id()
        recipient_identifier = self.recipient_input.text().strip()
        if not file_id or not recipient_identifier:
            QMessageBox.warning(self, "Missing info", "Select a file.")
            return
        if not recipient_identifier:
            QMessageBox.warning(self, "Missing info", "Enter a recipient.")
            return
        if not self.owner_id:
            QMessageBox.warning(self, "Not logged in", "Please login again.")
            return

        try:
            # 1) Fetch the owner's encrypted session key (RSA-encrypted for owner)
            print("line134")
            print(file_id)
            owner_enc_blob = get_owner_enc_session_key(file_id)
            if not owner_enc_blob:
                QMessageBox.warning(self, "Missing key",
                    "Owner session key not found. You need to save it during encryption. Tell me if you want me to add that.")
                return

            # 2) Decrypt it with the owner's private key to get the AES session key
            print("line127 sharing page")
            print(self.parent.current_user)
            owner_priv_enc = get_user_encrypted_private_key(self.parent.current_user)
            owner_rsa_pass = self.prompt_rsa_passphrase()

            if not owner_priv_enc or not owner_rsa_pass:
                QMessageBox.warning(self, "Missing credentials",
                    "Owner RSA credentials not available in session.")
                return
            
            if not is_rsa_passphrase_correct(owner_priv_enc, owner_rsa_pass):
                QMessageBox.warning(self, "Wrong password", "Wrong RSA password, try again.")
                return
            
            priv = RSA.import_key(owner_priv_enc, passphrase=owner_rsa_pass)
            session_key = PKCS1_OAEP.new(priv).decrypt(owner_enc_blob)

            # 3) Encrypt session key with recipient's public key
            recip_id = get_user_id(recipient_identifier)
            recip_pub_pem = get_user_public_key(recipient_identifier)
            if not recip_id or not recip_pub_pem:
                QMessageBox.warning(self, "Not found", "Recipient not found or missing public key.")
                return
            recip_pub = RSA.import_key(recip_pub_pem)
            enc_for_recipient = PKCS1_OAEP.new(recip_pub).encrypt(session_key)

            # 4) Store in file_shares
            insert_file_share(file_id, self.owner_id, recip_id, enc_for_recipient)
            QMessageBox.information(self, "Shared", f"Access granted to {recipient_identifier}.")
            self.recipient_input.clear()
            self.refresh_shares()

        except Exception as e:
            QMessageBox.critical(self, "Share failed", str(e))

    def handle_revoke(self, file_id, recipient_id):
        try:
            revoke_share(file_id, recipient_id)
            self.refresh_shares()
        except Exception as e:
            QMessageBox.critical(self, "Revoke failed", str(e))
