import os
import re

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox,
    QGridLayout, QAbstractItemView, QLineEdit, QFileDialog, QStackedLayout, QFrame,
    QProgressBar, QMessageBox, QToolButton, QFormLayout, QHeaderView, QComboBox,
    QDialog, QInputDialog, QSizePolicy, QSpacerItem, QGraphicsDropShadowEffect,
    QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QRegularExpression, QUrl
from PyQt5.QtGui import QColor, QRegularExpressionValidator, QFont, QIntValidator, QDesktopServices

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from auth_helper import (
    register_user, login_user, update_password, reset_password, get_user_email,
    get_user_id, get_user_public_key, get_user_encrypted_private_key,
    is_rsa_passphrase_correct,
)
from subscription_helper import (
    get_user_subscription_info, file_size_checker, get_all_subscription_tiers,
    format_file_size,
)
from newdb_operations import (
    get_file_owner, get_sharing_enc_session_key, has_file_access, list_file_shares,
    list_user_files, get_owner_enc_session_key, insert_file_share, revoke_share,
    list_drive_fragments,
)
from worker import (
    EmailSender, EncryptSplitWorker, DecryptReconstructWorker, DeleteFileWorker,
)
from vault_helper import user_vault_dir
from google_drive_integration import (
    _save_meta, get_credentials, get_google_identity, build_drive, ensure_trustshield_folder,
    ensure_trustshield_subfolder, disconnect_google, _meta_path,
    ensure_valid_credentials, list_fragments_in_folder, download_file_to,
    download_public_drive_file,
)
from db_config import get_connection
from fragmentCheck import get_file_id_from_any_fragment
from hashFile import hashFile
from verification_email import generate_code, send_verification_email
from recovery_helper import get_user_files, recover_missing_fragments


class RegisterPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent

        # ---- Page container + background
        self.setObjectName("RegisterPage")
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(0)

        # Center wrapper
        center = QHBoxLayout()
        center.addStretch(1)

        # ---- Card
        card = QFrame()
        card.setObjectName("Card")
        card.setFrameShape(QFrame.NoFrame)
        card.setMinimumWidth(420)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(28, 28, 28, 24)
        card_layout.setSpacing(16)

        # Drop shadow like CSS box-shadow
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(30)
        shadow.setXOffset(0)
        shadow.setYOffset(12)
        shadow.setColor(Qt.black.withAlpha(60) if hasattr(Qt.black, 'withAlpha') else Qt.black)
        card.setGraphicsEffect(shadow)

        # ---- Title
        self.title = QLabel("📝 Register for TrustShield")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setWeight(QFont.DemiBold)
        self.title.setFont(title_font)
        self.title.setAlignment(Qt.AlignHCenter)
        subtitle = QLabel("Create your account to get started")
        subtitle.setAlignment(Qt.AlignHCenter)
        subtitle.setObjectName("Subtitle")

        card_layout.addWidget(self.title)
        card_layout.addWidget(subtitle)

        # --- Inline alert (hidden by default)
        self.alert = QFrame(objectName="Alert")
        self.alert.setVisible(False)
        alert_layout = QVBoxLayout(self.alert)
        alert_layout.setContentsMargins(10, 6, 10, 6)

        self.alert_label = QLabel("")
        self.alert_label.setWordWrap(True)
        alert_layout.addWidget(self.alert_label)
        alert_layout.addWidget(self.alert) 

        # ---- Form
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        form.setFormAlignment(Qt.AlignTop)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(12)

        # Email
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("you@example.com")
        # Light email validation (doesn't change your logic)
        rx = QRegularExpression(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        self.email_input.setValidator(QRegularExpressionValidator(rx, self))
        form.addRow(QLabel("Email"), self.email_input)

        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username")
        form.addRow(QLabel("Username"), self.username_input)

        # Passwords (with show/hide toggle buttons)
        self.password_input = self._make_password_input("Password")
        form.addRow(QLabel("Password"), self.password_input)

        self.confirm_password_input = self._make_password_input("Confirm Password")
        form.addRow(QLabel("Confirm Password"), self.confirm_password_input)

        # RSA Passwords
        self.RSApassword_input = self._make_password_input("Enter RSA Password")
        form.addRow(QLabel("RSA Password"), self.RSApassword_input)

        self.confirm_RSApassword_input = self._make_password_input("Confirm RSA Password")
        form.addRow(QLabel("Confirm RSA Password"), self.confirm_RSApassword_input)

        # Subscription tier
        self.tier_combo = QComboBox()
        self.tiers = get_all_subscription_tiers()
        for tier in self.tiers:
            name = tier[1]
            description = tier[2]
            self.tier_combo.addItem(f"{name} : {description}", tier[0])

        form.addRow(QLabel("Subscription Tier"), self.tier_combo)

        card_layout.addLayout(form)

        # ---- Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.back_button = QPushButton("Back to Login")
        self.back_button.setObjectName("GhostButton")
        self.back_button.clicked.connect(lambda: self.parent.update_nav_visibility(0))

        btn_row.addWidget(self.back_button, 1)

        self.register_button = QPushButton("Create Account")
        self.register_button.setObjectName("PrimaryButton")
        self.register_button.setDefault(True)
        self.register_button.clicked.connect(self.handle_register)

        btn_row.addWidget(self.register_button, 2)

        card_layout.addLayout(btn_row)

        # Small footer spacer
        card_layout.addItem(QSpacerItem(0, 4, QSizePolicy.Minimum, QSizePolicy.Expanding))

        center.addWidget(card)
        center.addStretch(1)
        root.addLayout(center)

        # ---- Scoped stylesheet (only affects #RegisterPage)
        self.setStyleSheet("""
        /* Background like a subtle CSS gradient */
        #RegisterPage {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1,
                        stop:0 #0f172a, stop:1 #111827);
        }
        #RegisterPage QLabel {
            color: #e5e7eb;
        }
        #RegisterPage #Subtitle {
            color: #9ca3af;
            font-size: 12.5px;
            margin-top: -8px;
            margin-bottom: 4px;
        }
        #RegisterPage #Card {
            background: #0b1220;
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 16px;
        }
        /* Labels on the left side of the form */
        #RegisterPage QFormLayout > QLabel {
            color: #cbd5e1;
        }
        /* Inputs */
        #RegisterPage QLineEdit, #RegisterPage QComboBox {
            background: #0a0f1a;
            color: #e5e7eb;
            border: 1px solid #1f2937;
            border-radius: 10px;
            padding: 8px 12px;
            selection-background-color: #2563eb;
        }
        #RegisterPage QLineEdit:focus, #RegisterPage QComboBox:focus {
            border: 1px solid #3b82f6;
            outline: none;
        }
        #RegisterPage QComboBox QAbstractItemView {
            background: #0a0f1a;
            color: #e5e7eb;
            selection-background-color: #1f2937;
            border: 1px solid #1f2937;
        }
        /* Buttons */
        #RegisterPage QPushButton#PrimaryButton {
            background: #2563eb;
            border: none;
            color: #ffffff;
            padding: 10px 14px;
            border-radius: 10px;
            font-weight: 600;
        }
        #RegisterPage QPushButton#PrimaryButton:hover { background: #1d4ed8; }
        #RegisterPage QPushButton#PrimaryButton:pressed { background: #1e40af; }

        #RegisterPage QPushButton#GhostButton {
            background: transparent;
            border: 1px solid #334155;
            color: #cbd5e1;
            padding: 10px 14px;
            border-radius: 10px;
            font-weight: 500;
        }
        #RegisterPage QPushButton#GhostButton:hover {
            background: rgba(148,163,184,0.06);
        }

        /* Tool buttons inside password fields (eye icon area) */
        #RegisterPage QToolButton {
            border: none;
            padding: 0px 6px;
            color: #94a3b8;
        }
        #RegisterPage QToolButton:hover { color: #cbd5e1; }
                           
        #RegisterPage QMessageBox QLabel {
            color: black; /* reset label text color */
        }
                                
        """)

    # Reusable password field with show/hide toggle
    def _make_password_input(self, placeholder: str) -> QLineEdit:
        le = QLineEdit()
        le.setPlaceholderText(placeholder)
        le.setEchoMode(QLineEdit.Password)

        toggle = QToolButton(le)
        toggle.setCursor(Qt.PointingHandCursor)
        toggle.setToolTip("Show/Hide")
        toggle.setText("👁")
        toggle.setFixedWidth(28)

        m = le.textMargins()
        le.setTextMargins(m.left(), m.top(), m.right() + 28, m.bottom())

        def place_button():
            h = le.height()
            toggle.move(le.width() - toggle.width(), (h - toggle.height()) // 2)

        # Override resizeEvent properly
        original_resize = le.resizeEvent
        def new_resize(ev):
            original_resize(ev)
            place_button()
        le.resizeEvent = new_resize

        def on_click():
            if le.echoMode() == QLineEdit.Password:
                le.setEchoMode(QLineEdit.Normal)
            else:
                le.setEchoMode(QLineEdit.Password)
        toggle.clicked.connect(on_click)

        return le
    
    def handle_register(self):
        email = self.email_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_password_input.text()
        RSApass = self.RSApassword_input.text()
        confirmRSA = self.confirm_RSApassword_input.text()
        subscription_tier_id = self.tier_combo.currentData()

        # --- Basic empty check
        if not email or not username or not password or not confirm or not RSApass or not confirmRSA or not subscription_tier_id:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return
        
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid email address (e.g., name@example.com).")
            return
        # --- Password match check
        if password != confirm:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return

        # --- RSA password match check
        if RSApass != confirmRSA:
            QMessageBox.warning(self, "RSA Password Mismatch", "RSA Passwords do not match.")
            return

        # --- Password policy check (at least 8 characters, must be alphanumeric)
        if len(password) < 8 or not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+$", password):
            QMessageBox.warning(
                self,
                "Weak Password",
                "Password must be at least 8 characters long and contain both letters and numbers."
            )
            return
        
        if len(RSApass) < 8 or not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+$", RSApass):
            QMessageBox.warning(
                self,
                "Weak RSA Password",
                "RSA Password must be at least 8 characters long and contain both letters and numbers."
            )
            return

        # --- Call register_user
        success, message = register_user(email, username, password, RSApass, subscription_tier_id)
        if success:
            QMessageBox.information(self, "Success", message)
            self.parent.update_nav_visibility(0)  # Go back to login
        else:
            QMessageBox.warning(self, "Registration Failed", message)

class LoginPage(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        # ---- Global look (matches HTML) ----
        self.setStyleSheet("""
            
            QFrame#Card { background-color: #0b1220; border: 1px solid #222233;
                          border-radius: 18px; }
            QLabel#Title { background-color: transparent ; color: #e2e8f0; font-size: 22px; font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif; font-weight: 600; }
            QLabel#Subtitle { background-color: transparent; color: #9fb0c7; font-size: 13px; margin-bottom: 6px; }
            QLabel#FieldLabel { background-color: transparent; color: #cbd5e1; font-size: 13px; }
            QLineEdit { background-color: #0a1222; border: 1px solid #334155;
                        border-radius: 12px; padding: 10px 12px; color: #e2e8f0; }
            QLineEdit:focus { border: 1px solid #64748b; }
            QPushButton#Primary { background-color: #2563eb; color: white; font-weight: 600;
                                  border: none; border-radius: 12px; padding: 12px 14px; }
            QPushButton#Secondary { background-color: #0a1222; color: #cbd5e1; font-weight: 600;
                                    border: 1px solid #334155; border-radius: 12px; padding: 12px 14px; }
            QPushButton#Link { background: transparent; border: none; color: #93c5fd;
                               text-align: right; padding: 0; font-size: 12px; }
            QFrame#Alert { background-color: #878d96; border: 1px solid #374151;
                           border-radius: 12px; padding: 10px 12px; }
            QFrame#Alert QLabel { background-color: transparent; }
            QMessageBox {
                background-color: white;
                color: black;
            }
            QMessageBox QLabel {
                color: black;
            }
        """)

        # ---- Root layout fills window ----
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Use spacers to keep the card vertically centered
        root.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # ---- Card ----
        self.card = QFrame(objectName="Card")
        self.card.setFixedWidth(380)  # matches HTML width
        self.card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)

        # Drop shadow like the HTML box-shadow
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(0, 0, 0, 90))
        self.card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(28, 28, 28, 28)
        card_layout.setSpacing(12)

        title = QLabel("🔐 Login to TrustShield", objectName="Title")
        subtitle = QLabel("Welcome back. Please sign in to continue.", objectName="Subtitle")

        self.alert = QFrame(objectName="Alert")
        self.alert.setVisible(False)
        alert_layout = QVBoxLayout(self.alert)
        alert_layout.setContentsMargins(10, 6, 10, 6)
        self.alert_label = QLabel("")
        alert_layout.addWidget(self.alert_label)

        # Fields
        lbl_id = QLabel("Email or Username", objectName="FieldLabel")
        self.identifier_input = QLineEdit()
        self.identifier_input.setPlaceholderText("Email or Username")

        lbl_pw = QLabel("Password", objectName="FieldLabel")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Password")

        # Buttons row (Login + Register)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.login_button = QPushButton("Login", objectName="Primary")
        self.register_button = QPushButton("Register", objectName="Secondary")
        row.addWidget(self.login_button)
        row.addWidget(self.register_button)

        # Link row (Forgot Password?)
        link_row = QHBoxLayout()
        link_row.addStretch(1)
        self.forgot_button = QPushButton("Forgot Password?", objectName="Link")
        self.forgot_button.setCursor(Qt.PointingHandCursor)
        link_row.addWidget(self.forgot_button)

        # Assemble
        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)
        card_layout.addWidget(self.alert)
        card_layout.addWidget(lbl_id)
        card_layout.addWidget(self.identifier_input)
        card_layout.addWidget(lbl_pw)
        card_layout.addWidget(self.password_input)
        card_layout.addLayout(row)
        card_layout.addLayout(link_row)

        # Center the card horizontally
        center_row = QHBoxLayout()
        center_row.addStretch(1)
        center_row.addWidget(self.card)
        center_row.addStretch(1)
        root.addLayout(center_row)

        root.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Expand to fill window
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # ---- Connections ----
        self.login_button.clicked.connect(self.handle_login)
        self.register_button.clicked.connect(lambda: self.parent.update_nav_visibility(1))
        self.forgot_button.clicked.connect(self.handle_forgot_password)
        self.identifier_input.returnPressed.connect(self.handle_login)
        self.password_input.returnPressed.connect(self.handle_login)

    # ---- Helpers ----

    def show_alert(self, text, error=False):
        self.alert_label.setText(text or "")
        self.alert.setVisible(bool(text))
        # just change the label color; keeps your global stylesheet intact
        if error:
            self.alert_label.setStyleSheet("color: #ef4444;")   # red
        else:
            self.alert_label.setStyleSheet("color: #e2e8f0;")   # default

    # ---- Logic (reuses your existing functions) ----
    def handle_login(self):
        identifier = self.identifier_input.text().strip()
        password = self.password_input.text()

        if not identifier or not password:
            self.show_alert("No inputs detected.",error=True)
            return

        success, message, email, username = login_user(identifier, password)
        if success:
            
            self.show_alert("2FA code sent. Please verify.")
            code = generate_code()
            action = "login"
            print(f"The code for {action} is: {code}")

            self._email_thread = EmailSender(email, code, action, self)
            self._email_thread.start()

            def resend_code():
                new_code = generate_code()
                self._email_thread = EmailSender(email, new_code, action, self)
                self._email_thread.start()
                return new_code

            dialog = TwoFADialog(expected_code=code, resend_callback=resend_code, duration_seconds=30)

            if dialog.exec_() == QDialog.Accepted:
                self.parent.current_user = email
                sub_info = get_user_subscription_info(identifier)
                if sub_info:
                    self.parent.user_subscription_tier = sub_info.get("tier_name")
                    self.parent.user_max_file_size = sub_info.get("max_file_size")
                vault = user_vault_dir(email)
                ok, _, reason = ensure_valid_credentials(vault, interactive=False)
                self.parent.google_drive_connected = ok
                
                if not ok:
                    QMessageBox.information(
                        self, "Google Drive",
                        "Your Google Drive link is not active (or token expired).\n"
                        "If you plan to use cloud storage, please reconnect it in your Profile."
                    )
                self.parent.profile_page.set_user_info(email, username)
                QMessageBox.information(self, "Success", message or "Login successful.")
                self.alert.setVisible(False)
                self.parent.update_nav_visibility(2)
            else:
                self.show_alert("2FA verification fail.", error=True)
        else:
            self.show_alert("Invalid email/username or password.",error = True)
            self.identifier_input.clear()
            self.password_input.clear()
            self.identifier_input.setFocus()

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
        

        # ----- Window basics
        self.setObjectName("TwoFA")
        self.setWindowTitle("Two-Factor Authentication")
        self.setMinimumWidth(420)
        self.setModal(True)

        # ----- Root layout (center the card)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        center_row = QHBoxLayout()
        center_row.addStretch(1)

        # ----- Card (like HTML card)
        card = QFrame(objectName="Card")
        card.setFrameShape(QFrame.NoFrame)
        card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 14)
        shadow.setColor(QColor(0, 0, 0, 90))
        card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(28, 28, 28, 24)
        card_layout.setSpacing(14)

        # ----- Title + subtitle
        title = QLabel("🔐 Verify it’s you", objectName="Title")
        subtitle = QLabel("Enter the 2FA code we sent to your email.", objectName="Subtitle")
        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)

        # ----- Inline alert (info/error), hidden by default
        self.alert = QFrame(objectName="Alert")
        self.alert.setVisible(False)
        alert_layout = QHBoxLayout(self.alert)
        alert_layout.setContentsMargins(10, 6, 10, 6)
        self.alert_label = QLabel("", objectName="AlertText")
        self.alert_label.setWordWrap(True)
        alert_layout.addWidget(self.alert_label)
        card_layout.addWidget(self.alert)

        # ----- Code input
        self.info_label = QLabel("Verification code", objectName="FieldLabel")
        card_layout.addWidget(self.info_label)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter verification code")
        self.input.setMaxLength(12)
        self.input.returnPressed.connect(self.verify)
        self.input.setObjectName("CodeInput")
        card_layout.addWidget(self.input)

        # ----- Countdown
        self.countdown_label = QLabel(self._format_time(self.seconds_left), objectName="Countdown")
        self.countdown_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.countdown_label)

        # ----- Buttons row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.submit_btn = QPushButton("Verify", objectName="Primary")
        self.submit_btn.clicked.connect(self.verify)
        self.resend_btn = QPushButton("Resend code", objectName="Secondary")
        self.resend_btn.setEnabled(False)
        self.resend_btn.clicked.connect(self._handle_resend)
        btn_row.addWidget(self.resend_btn, 1)
        btn_row.addWidget(self.submit_btn, 1)
        card_layout.addLayout(btn_row)

        center_row.addWidget(card)
        center_row.addStretch(1)
        root.addLayout(center_row)

        root.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # ----- Scoped stylesheet (applies only to this dialog)
        self.setStyleSheet("""
        #TwoFA {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #0f172a, stop:1 #111827);
            font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif;
            color: #e5e7eb;
        }
        #TwoFA #Card {
            background-color: #0b1220;
            border: 1px solid #1f2230;
            border-radius: 18px;
        }
        #TwoFA QLabel#Title {
            font-size: 20px;
            font-weight: 600;
            color: #e5e7eb;
            margin-bottom: 2px;
        }
        #TwoFA QLabel#Subtitle {
            font-size: 13px;
            color: #9fb0c7;
            margin-bottom: 8px;
        }
        #TwoFA QLabel#FieldLabel {
            font-size: 13px;
            color: #cbd5e1;
        }
        #TwoFA QLineEdit#CodeInput {
            background: #0a1222;
            color: #e5e7eb;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 12px;
            font-size: 16px;
            letter-spacing: 2px;
        }
        #TwoFA QLineEdit#CodeInput:focus {
            border: 1px solid #64748b;
        }
        #TwoFA QLabel#Countdown {
            color: #93c5fd;
            font-size: 12.5px;
            margin-top: 2px;
            margin-bottom: 2px;
        }
        /* Buttons */
        #TwoFA QPushButton#Primary {
            background-color: #2563eb;
            color: white;
            font-weight: 600;
            border: none;
            border-radius: 12px;
            padding: 10px 12px;
        }
        #TwoFA QPushButton#Primary:hover { background: #1d4ed8; }
        #TwoFA QPushButton#Primary:pressed { background: #1e40af; }

        #TwoFA QPushButton#Secondary {
            background-color: #0a1222;
            color: #cbd5e1;
            font-weight: 600;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 10px 12px;
        }
        #TwoFA QPushButton#Secondary:disabled {
            color: #6b7280;
            border-color: #2a3342;
            background-color: #0a0f1a;
        }

        /* Inline alert styles */
        #TwoFA #Alert {
            border: 1px solid #374151;
            border-radius: 10px;
            background-color: rgba(148,163,184,0.12);
        }
        #TwoFA #Alert[alertType="error"] {
            border-color: #fca5a5;
            background-color: #fee2e2;
        }
        #TwoFA #Alert[alertType="success"] {
            border-color: #86efac;
            background-color: #dcfce7;
        }
        #TwoFA #Alert[alertType="info"] {
            border-color: #93c5fd;
            background-color: #dbeafe;
        }
        #TwoFA #Alert QLabel#AlertText {
            color: #202329;
        }
        #TwoFA #Alert[alertType="error"] QLabel#AlertText { color: #7f1d1d; }
        #TwoFA #Alert[alertType="success"] QLabel#AlertText { color: #14532d; }
        #TwoFA #Alert[alertType="info"] QLabel#AlertText { color: #1e3a8a; }
        """)

        # ----- Timer for countdown
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    # ========= helper UI methods (non-breaking) =========

    def _format_time(self, secs):
        m, s = divmod(secs, 60)
        return f"Resend available in {m:02d}:{s:02d}"

    def _show_alert(self, text: str, kind: str = "info"):
        """Inline alert in the dialog (doesn't replace QMessageBox; purely visual)."""
        self.alert_label.setText(text or "")
        self.alert.setProperty("alertType", kind)
        # refresh style to apply property change
        self.alert.style().unpolish(self.alert)
        self.alert.style().polish(self.alert)
        self.alert.setVisible(bool(text))

    
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
            self._show_alert("Resend not available in this flow.", "info")
            return
        try:
            new_code = self.resend_callback()
            self.expected_code = new_code
            QMessageBox.information(self, "Code resent",
                                    "A new verification code has been sent to your email.")
            self._show_alert("New code sent. Check your inbox.", "success")
            self._restart_timer()
            self.input.clear()
            self.input.setFocus()
        except Exception as e:
            QMessageBox.warning(self, "Resend failed", f"Could not resend code.\n{e}")
            self._show_alert("Could not resend code. Please try again.", "error")

    def verify(self):
        if self.input.text().strip() == self.expected_code:
            if self.timer.isActive():
                self.timer.stop()
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Invalid verification code.")
            self._show_alert("Invalid verification code.", "error")

    def closeEvent(self, event):
        if self.timer.isActive():
            self.timer.stop()
        super().closeEvent(event)

class ResetPasswordDialog(QDialog):
    def __init__(self, email, expected_code):
        super().__init__()
        self.setObjectName("ResetPwd")
        self.setWindowTitle("Reset Password with 2FA")
        self.setModal(True)
        self.setMinimumWidth(420)

        self.email = email
        self.expected_code = expected_code

        # ===== Root layout (centers the card) =====
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        row = QHBoxLayout()
        row.addStretch(1)

        # ===== Card =====
        card = QFrame(objectName="Card")
        card.setFrameShape(QFrame.NoFrame)
        card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 14)
        shadow.setColor(QColor(0, 0, 0, 90))
        card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(28, 28, 28, 24)
        card_layout.setSpacing(14)

        # Title + subtitle
        title = QLabel("🔐 Reset your password", objectName="Title")
        subtitle = QLabel(f"We sent a code to: {email}", objectName="Subtitle")
        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)

        # Inline alert (hidden by default; optional to use)
        self.alert = QFrame(objectName="Alert")
        self.alert.setVisible(False)
        alert_layout = QHBoxLayout(self.alert)
        alert_layout.setContentsMargins(10, 6, 10, 6)
        self.alert_label = QLabel("", objectName="AlertText")
        self.alert_label.setWordWrap(True)
        alert_layout.addWidget(self.alert_label)
        card_layout.addWidget(self.alert)

        # Form fields
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        form.setFormAlignment(Qt.AlignTop)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(12)

        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter verification code")
        form.addRow(QLabel("Verification Code:", objectName="FieldLabel"), self.code_input)

        self.new_password = self._make_password_input("New Password")
        form.addRow(QLabel("New Password:", objectName="FieldLabel"), self.new_password)

        self.confirm_password = self._make_password_input("Confirm Password")
        form.addRow(QLabel("Confirm Password:", objectName="FieldLabel"), self.confirm_password)

        card_layout.addLayout(form)

        # Buttons
        self.submit_btn = QPushButton("Reset Password", objectName="Primary")
        self.submit_btn.clicked.connect(self.reset_password)
        card_layout.addWidget(self.submit_btn)

        row.addWidget(card)
        row.addStretch(1)
        root.addLayout(row)
        root.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # ===== Scoped stylesheet (only affects #ResetPwd) =====
        self.setStyleSheet("""
        #ResetPwd {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #0f172a, stop:1 #111827);
            font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif;
            color: #e5e7eb;
        }
        #ResetPwd #Card {
            background-color: #0b1220;
            border: 1px solid #1f2230;
            border-radius: 18px;
        }
        #ResetPwd QLabel#Title {
            font-size: 20px;
            font-weight: 600;
            color: #e5e7eb;
            margin-bottom: 2px;
        }
        #ResetPwd QLabel#Subtitle {
            font-size: 12.5px;
            color: #9fb0c7;
            margin-bottom: 8px;
        }
        #ResetPwd QLabel#FieldLabel {
            font-size: 13px;
            color: #cbd5e1;
        }
        #ResetPwd QLineEdit {
            background: #0a1222;
            color: #e5e7eb;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 10px 12px;
        }
        #ResetPwd QLineEdit:focus {
            border: 1px solid #64748b;
        }
        #ResetPwd QPushButton#Primary {
            background-color: #2563eb;
            color: white;
            font-weight: 600;
            border: none;
            border-radius: 12px;
            padding: 12px 14px;
        }
        #ResetPwd QPushButton#Primary:hover { background: #1d4ed8; }
        #ResetPwd QPushButton#Primary:pressed { background: #1e40af; }
        
        #ResetPwd QToolButton {
            border: none;
            padding: 0px 6px;
            color: #94a3b8;
        }
        #ResetPwd QToolButton:hover { color: #cbd5e1; }

        /* Inline alert styles */
        #ResetPwd #Alert {
            border: 1px solid #374151;
            border-radius: 10px;
            background-color: rgba(148,163,184,0.12);
        }
        #ResetPwd #Alert[alertType="error"] {
            border-color: #fca5a5;
            background-color: #fee2e2;
        }
        #ResetPwd #Alert[alertType="success"] {
            border-color: #86efac;
            background-color: #dcfce7;
        }
        #ResetPwd #Alert[alertType="info"] {
            border-color: #93c5fd;
            background-color: #dbeafe;
        }
        #ResetPwd #Alert QLabel#AlertText { color: #e5e7eb; }
        #ResetPwd #Alert[alertType="error"] QLabel#AlertText { color: #7f1d1d; }
        #ResetPwd #Alert[alertType="success"] QLabel#AlertText { color: #14532d; }
        #ResetPwd #Alert[alertType="info"] QLabel#AlertText { color: #1e3a8a; }
        """)

    # ------- small helper for inline alerts (optional to use) -------
    def _show_alert(self, text: str, kind: str = "info"):
        self.alert_label.setText(text or "")
        self.alert.setProperty("alertType", kind)
        self.alert.style().unpolish(self.alert)
        self.alert.style().polish(self.alert)
        self.alert.setVisible(bool(text))
    
    # ------- password field with show/hide eye -------
    def _make_password_input(self, placeholder: str) -> QLineEdit:
        le = QLineEdit()
        le.setPlaceholderText(placeholder)
        le.setEchoMode(QLineEdit.Password)

        toggle = QToolButton(le)
        toggle.setCursor(Qt.PointingHandCursor)
        toggle.setToolTip("Show/Hide")
        toggle.setText("👁")
        toggle.setFixedWidth(28)

        m = le.textMargins()
        le.setTextMargins(m.left(), m.top(), m.right() + 28, m.bottom())

        def place_button():
            h = le.height()
            toggle.move(le.width() - toggle.width(), (h - toggle.height()) // 2)

        original_resize = le.resizeEvent
        def new_resize(ev):
            original_resize(ev)
            place_button()
        le.resizeEvent = new_resize

        def on_click():
            if le.echoMode() == QLineEdit.Password:
                le.setEchoMode(QLineEdit.Normal)
            else:
                le.setEchoMode(QLineEdit.Password)
        toggle.clicked.connect(on_click)

        return le

    # ------- your original logic (unchanged) -------
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
        
        if len(new_pass) < 8 or not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]+$", new_pass):
            QMessageBox.warning(
                self,
                "Weak Password",
                "Password must be at least 8 characters long and contain both letters and numbers."
            )
            return

        success, message = reset_password(self.email, new_pass)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Error", message)


class EncryptPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.setObjectName("EncryptPage")

        # ===== Root layout (NO extra margins; ContentWrap already has 24px) =====
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)   # << important
        root.setSpacing(10)                   # match sidebar spacing

        # ===== Single card that expands to fill the content width =====
        card = QFrame(objectName="Card")
        card.setFrameShape(QFrame.NoFrame)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)  # << expand horizontally
        # remove the old hard minimum of 720 so it just fills the available area
        # card.setMinimumWidth(720)  # (removed)

        # Subtle shadow
        try:
            shadow = QGraphicsDropShadowEffect(self)
            shadow.setBlurRadius(36)
            shadow.setOffset(0, 12)
            shadow.setColor(QColor(0, 0, 0, 110))
            card.setGraphicsEffect(shadow)
        except Exception:
            pass

        card_layout = QVBoxLayout(card)
        # Inner padding of the card (like CSS padding)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(12)

        # ===== Title =====
        header = QHBoxLayout()
        title = QLabel("🔐 Encrypt & Split", objectName="Title")
        subtitle = QLabel("Secure your file, then split shards across destinations.", objectName="Subtitle")
        subtitle.setWordWrap(True)
        header.addWidget(title)
        header.addStretch(1)
        card_layout.addLayout(header)
        card_layout.addWidget(subtitle)

        # ===== File selection =====
        sec1 = QLabel("Source File", objectName="SectionTitle")
        card_layout.addWidget(sec1)

        file_row = QHBoxLayout()
        file_row.setSpacing(10)
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Choose a file to encrypt…")
        self.file_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        file_browse_btn = QPushButton("Browse File", objectName="Secondary")
        file_browse_btn.clicked.connect(self.browse_file)
        file_row.addWidget(QLabel("File:", objectName="FieldLabel"))
        file_row.addWidget(self.file_input, 1)
        file_row.addWidget(file_browse_btn)
        card_layout.addLayout(file_row)
        card_layout.addWidget(self._line())

        # ===== RSA section =====
        sec2 = QLabel("Your RSA Password", objectName="SectionTitle")
        card_layout.addWidget(sec2)

        rsa_grid = QGridLayout()
        rsa_grid.setHorizontalSpacing(12)
        rsa_grid.setVerticalSpacing(10)

        r = 0
        rsa_lbl = QLabel("Password:", objectName="FieldLabel")
        self.rsa_input = QLineEdit()
        self.rsa_input.setPlaceholderText("Enter password")
        self.rsa_input.setEchoMode(QLineEdit.Password)
        self.rsa_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        rsa_grid.addWidget(rsa_lbl, r, 0)
        rsa_grid.addWidget(self.rsa_input, r, 1, 1, 2)
        r += 1

        rsa_c_lbl = QLabel("Confirm:", objectName="FieldLabel")
        self.rsa_confirm_input = QLineEdit()
        self.rsa_confirm_input.setPlaceholderText("Confirm password")
        self.rsa_confirm_input.setEchoMode(QLineEdit.Password)
        self.rsa_confirm_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        rsa_grid.addWidget(rsa_c_lbl, r, 0)
        rsa_grid.addWidget(self.rsa_confirm_input, r, 1, 1, 2)
        r += 1

        card_layout.addLayout(rsa_grid)
        card_layout.addWidget(self._line())

        # ===== Storage selection =====
        sec3 = QLabel("Destinations", objectName="SectionTitle")
        card_layout.addWidget(sec3)

        store_row = QHBoxLayout()
        store_row.setSpacing(10)

        self.cloud_cb = QPushButton("Store in Google Drive")
        self.cloud_cb.setCheckable(True)
        self.cloud_cb.setObjectName("Toggle")

        self.local_cb = QPushButton("Store Local 1")
        self.local_cb.setCheckable(True)
        self.local_cb.setChecked(True)
        self.local_cb.setObjectName("Toggle")
        self.local_cb.toggled.connect(self.on_local1_toggled)

        self.add_local2_cb = QCheckBox("+ extra local path")
        self.add_local2_cb.setToolTip("Add a second local folder for fragments")
        self.add_local2_cb.setEnabled(self.local_cb.isChecked())

        hint = QLabel("Tip: Shards are split evenly across selected destinations.", objectName="Hint")

        store_row.addWidget(self.cloud_cb)
        store_row.addWidget(self.local_cb)
        store_row.addWidget(self.add_local2_cb)
        store_row.addStretch(1)
        card_layout.addLayout(store_row)
        card_layout.addWidget(hint)
        card_layout.addWidget(self._line())

        # ===== Output folders =====
        sec4 = QLabel("Output Folders", objectName="SectionTitle")
        card_layout.addWidget(sec4)

        # Local 1
        self.local1_row = QWidget()
        local1 = QHBoxLayout(self.local1_row)
        local1.setContentsMargins(0, 0, 0, 0)
        local1.setSpacing(10)
        local1.addWidget(QLabel("Local 1 Folder:", objectName="FieldLabel"))
        self.output_folder = QLineEdit()
        self.output_folder.setPlaceholderText("Select output folder for fragments (Local 1)")
        self.output_folder.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        output_browse_btn = QPushButton("Browse Folder", objectName="Secondary")
        output_browse_btn.clicked.connect(self.browse_output_folder)
        local1.addWidget(self.output_folder, 1)
        local1.addWidget(output_browse_btn)
        self.local1_row.setVisible(self.local_cb.isChecked())
        card_layout.addWidget(self.local1_row)

        # Local 2
        self.local2_row = QWidget()
        local2 = QHBoxLayout(self.local2_row)
        local2.setContentsMargins(0, 0, 0, 0)
        local2.setSpacing(10)
        local2.addWidget(QLabel("Local 2 Folder:", objectName="FieldLabel"))
        self.output_folder2 = QLineEdit()
        self.output_folder2.setPlaceholderText("Select additional local folder for fragments (Local 2)")
        self.output_folder2.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        output_browse_btn2 = QPushButton("Browse Folder", objectName="Secondary")
        output_browse_btn2.clicked.connect(self.browse_output_folder2)
        local2.addWidget(self.output_folder2, 1)
        local2.addWidget(output_browse_btn2)
        self.local2_row.setVisible(False)
        card_layout.addWidget(self.local2_row)
        card_layout.addWidget(self._line())

        # ===== Shards (n, k) =====
        sec5 = QLabel("Erasure Coding", objectName="SectionTitle")
        card_layout.addWidget(sec5)

        shard_row = QHBoxLayout()
        shard_row.setSpacing(10)
        shard_row.addWidget(QLabel("n:", objectName="FieldLabel"))
        self.n_input = QLineEdit()
        self.n_input.setPlaceholderText("Total shards (n)")
        self.n_input.setValidator(QIntValidator(2, 256, self))
        self.n_input.setFixedWidth(140)
        shard_row.addWidget(self.n_input)

        shard_row.addWidget(QLabel("k:", objectName="FieldLabel"))
        self.k_input = QLineEdit()
        self.k_input.setPlaceholderText("Required shards (k)")
        self.k_input.setValidator(QIntValidator(1, 256, self))
        self.k_input.setFixedWidth(140)
        shard_row.addWidget(self.k_input)
        shard_row.addStretch(1)
        card_layout.addLayout(shard_row)

        # ===== Progress =====
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFormat("%p% - %v/%m")
        self.progress_bar.setFixedHeight(22)
        card_layout.addWidget(self.progress_bar)

        # ===== Primary action =====
        self.go_btn = QPushButton("Encrypt and Split", objectName="Primary")
        self.go_btn.clicked.connect(self.encrypt_and_split)
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_row.addWidget(self.go_btn)
        card_layout.addLayout(btn_row)

        # ===== Status =====
        self.status = QLabel("Status:")
        self.status.setObjectName("StatusBar")
        self.status.setMinimumHeight(34)
        self.status.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card_layout.addWidget(self.status)

        # Attach card to root (no extra centering stretches to avoid phantom margins)
        root.addWidget(card)

        # Connections
        self.add_local2_cb.toggled.connect(self.on_add_local2_toggled)
        self.local_cb.toggled.connect(self._sync_storage_ui)

        # ===== Scoped stylesheet (unchanged visual theme) =====
        self.setStyleSheet("""
        #EncryptPage {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #0f172a, stop:1 #111827);
            color: #e5e7eb;
            font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif;
        }
        #EncryptPage #Card {
            background: #0b1220;
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 18px;
        }
        #EncryptPage QLabel#Title {
            font-size: 20px;
            font-weight: 600;
            color: #e5e7eb;
        }
        #EncryptPage QLabel#Subtitle {
            color: #9fb0c7;
            font-size: 13px;
            margin-top: -4px;
        }
        #EncryptPage QLabel#SectionTitle {
            margin-top: 4px;
            font-size: 13px;
            letter-spacing: .2px;
            color: #cbd5e1;
            opacity: .9;
        }
        #EncryptPage QLabel#FieldLabel { color: #cbd5e1; }
        #EncryptPage QLabel#Hint { color: #93a4bd; font-size: 12px; margin-top: -6px; }

        #EncryptPage QLineEdit {
            background: #0a1222;
            color: #e5e7eb;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 10px 12px;
        }
        #EncryptPage QLineEdit:focus { border: 1px solid #64748b; }
                           
                           
        #EncryptPage QPushButton#Toggle {
            text-align: left;
            padding: 10px 12px;
            border-radius: 12px;
            border: 1px solid #2b3445;
            color: #e5e7eb;
            background: #0a1222;
            font-weight: 600;
        }
        #EncryptPage QPushButton#Toggle:hover { background: #0d1629; color: white }
        #EncryptPage QPushButton#Toggle:checked { background: #01ac26; border-color: #2c3f59; color: white }
        #EncryptPage QCheckBox { color: #ffffff; }
        #EncryptPage QCheckBox:disabled { color: #ffffff; }
                           
        
        #EncryptPage QPushButton#Primary {
            background: #2563eb;
            color: white;
            font-weight: 600;
            border: none;
            border-radius: 12px;
            padding: 12px 16px;
            min-width: 180px;
        }
        #EncryptPage QPushButton#Primary:hover { background: #1d4ed8; }
        #EncryptPage QPushButton#Primary:pressed { background: #1e40af; }

        #EncryptPage QPushButton#Secondary {
            background: #0a1222;
            color: #cbd5e1;
            font-weight: 600;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 10px 12px;
        }
        #EncryptPage QPushButton#Secondary:hover { background: #0d1629; }

        #EncryptPage QProgressBar {
            background: #0a1222;
            border: 1px solid #334155;
            border-radius: 10px;
            text-align: center;
            height: 22px;
        }
        #EncryptPage QProgressBar::chunk {
            border-radius: 10px;
            margin: 1px;
            background-color: #2563eb;
        }

        #EncryptPage QLabel#StatusBar {
            background: #0a1222;
            border: 1px solid #334155;
            border-radius: 10px;
            padding-left: 8px;
            color: #e5e7eb;
        }
        """)


    # ===== Utility line =====
    def _line(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("color: #1e293b;")
        return line

    # ===== File pickers =====
    def browse_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file:
            self.file_input.setText(file)

    def browse_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output_folder.setText(folder)

    def browse_output_folder2(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder 2")
        if folder:
            self.output_folder2.setText(folder)

    # ===== Toggles =====
    def on_local1_toggled(self, checked: bool):
        self.local1_row.setVisible(checked)
        self.add_local2_cb.setEnabled(checked)
        if not checked:
            self.output_folder.clear()

    def on_add_local2_toggled(self, checked: bool):
        self.local2_row.setVisible(checked)
        if not checked:
            self.output_folder2.clear()

    def _sync_storage_ui(self, _=None):
        # Reserved for future UI sync; logic kept as-is.
        pass

    # ===== Dialogs =====
    def prompt_backup_opt_in(self) -> bool:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle("Enable Fragment Recovery (Local Backup)?")
        box.setText(
            "To enable fragment recovery later, the app can create a LOCAL backup of the "
            "encrypted fragments on this device.\n\n"
            "If you choose No, fragment recovery will NOT be possible if fragments are lost."
        )
        box.setInformativeText("Create the local backup now?")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.Yes)
        choice = box.exec_()
        return choice == QMessageBox.Yes

    # ===== Logic (unchanged) =====
    def encrypt_and_split(self):
        try:
            # ---- helpers ----
            def set_err(msg: str):
                self.status.setText(f"Error: {msg}")
                self.status.setStyleSheet("color: #ef4444; background-color: #0a1222; "
                                          "border: 1px solid #334155; border-radius: 10px; padding-left: 8px;")
                return False

            def set_info(msg: str):
                self.status.setText(msg)
                self.status.setStyleSheet("color: #e5e7eb; background-color: #0a1222; "
                                          "border: 1px solid #334155; border-radius: 10px; padding-left: 8px;")

            def is_writable_dir(path: str) -> bool:
                return os.path.isdir(path) and os.access(path, os.W_OK)

            def human_bytes(n: int) -> str:
                for unit in ('B','KB','MB','GB','TB'):
                    if n < 1024 or unit == 'TB':
                        return f"{n:.1f} {unit}"
                    n /= 1024
                return f"{n:.1f} TB"

            # ---- gather inputs ----
            filepath = (self.file_input.text() or "").strip()
            n_text = (self.n_input.text() or "").strip()
            k_text = (self.k_input.text() or "").strip()
            output_folder = (self.output_folder.text() or "").strip()
            password = self.rsa_input.text()
            confirm  = self.rsa_confirm_input.text()

            store_in_cloud  = self.cloud_cb.isChecked()
            store_in_local  = self.local_cb.isChecked()
            store_in_local2 = self.add_local2_cb.isChecked()
            output_folder2  = (self.output_folder2.text() or "").strip() if store_in_local2 else ""

            # ---- validate base fields ----
            if not filepath:
                return set_err("Please select a file.")
            if not os.path.isfile(filepath):
                return set_err("File does not exist or is not a regular file.")

            # n, k integers
            if not n_text or not k_text:
                return set_err("Please enter both n (total shards) and k (required shards).")
            try:
                n = int(n_text)
                k = int(k_text)
            except ValueError:
                return set_err("n and k must be whole numbers.")

            if n < 2 or n > 256:
                return set_err("n must be between 2 and 256.")
            if k < 1 or k > n:
                return set_err("k must be at least 1 and no greater than n.")

            # storage
            m = int(bool(store_in_cloud)) + int(bool(store_in_local)) + int(bool(store_in_local2))
            if m == 0:
                return set_err("Choose at least one storage location (Drive / Local 1 / Local 2).")
            if n < m:
                return set_err(f"n must be at least the number of selected destinations ({m}).")

            # passwords
            if password != confirm:
                return set_err("Passwords do not match.")
            if len(password) < 8:
                return set_err("Password must be at least 8 characters long.")

            # local dirs
            if store_in_local:
                if not is_writable_dir(output_folder):
                    return set_err("Invalid or non-writable output folder (Local 1).")
            if store_in_local2:
                if not is_writable_dir(output_folder2):
                    return set_err("Invalid or non-writable output folder (Local 2).")
                if os.path.abspath(output_folder2) == os.path.abspath(output_folder):
                    return set_err("Local 2 folder must be different from Local 1 folder.")

            # plan limit
            try:
                file_size = os.path.getsize(filepath)
                limit = getattr(self.parent, "user_max_file_size", None)
                if isinstance(limit, (int, float)) and limit > 0 and file_size > limit:
                    return set_err(
                        f"File is too large for your plan: {human_bytes(file_size)} > {human_bytes(int(limit))}."
                    )
            except Exception:
                pass

            # Ensure Drive linked
            if store_in_cloud:
                email = getattr(self.parent, "current_user", "") or ""
                ok, _, reason = ensure_valid_credentials(user_vault_dir(email), interactive=True)
                if not ok:
                    self.parent.google_drive_connected = False
                    if hasattr(self, "_refresh_cloud_enable"):
                        self._refresh_cloud_enable()
                    return set_err("Google Drive is not connected. Re-link it in Profile first.")
                self.parent.google_drive_connected = True

            # UI busy
            self.go_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            set_info("Processing...")

            # backup opt in
            backup_opt_in = self.prompt_backup_opt_in()

            # destinations & distribution
            destinations = []
            if store_in_cloud: destinations.append({"kind": "drive"})
            if store_in_local: destinations.append({"kind": "local", "path": output_folder})
            if store_in_local2: destinations.append({"kind": "local", "path": output_folder2})

            base = n // m
            rem = n % m
            counts = [base + (1 if i < rem else 0) for i in range(m)]
            distribution_plan = [
                {"index": i, "kind": d["kind"], "path": d.get("path", ""), "count": counts[i]}
                for i, d in enumerate(destinations)
            ]

            # worker
            user_identifier = self.parent.current_user
            user_subscription_tier = self.parent.user_subscription_tier
            user_max_file_size = self.parent.user_max_file_size

            print("line291" + user_identifier if user_identifier else "line291")

            self.worker = EncryptSplitWorker(
                filepath, output_folder, n, k, password,
                user_identifier, user_subscription_tier,
                user_max_file_size,
                store_in_cloud=store_in_cloud,
                store_in_local=store_in_local,
                backup_opt_in=backup_opt_in,
                store_in_local2=store_in_local2,
                local_output_folder2=output_folder2,
                distribution_plan=distribution_plan,
            )
            self.worker.finished.connect(self.on_encrypt_finished)
            self.worker.error.connect(self.on_encrypt_error)
            self.worker.progress.connect(self.on_progress_update)
            self.worker.start()

        except Exception as e:
            self.status.setText(f"Error: {e}")
            self.status.setStyleSheet("color: #ef4444; background-color: #0a1222; "
                                      "border: 1px solid #334155; border-radius: 10px; padding-left: 8px;")
            self.go_btn.setEnabled(True)
            self.progress_bar.setVisible(False)

    def on_progress_update(self, percentage, message):
        self.progress_bar.setValue(percentage)
        self.status.setText(f"Status: {message}")

    def on_encrypt_finished(self, message):
        self.status.setText(f"Status: {message}")
        self.status.setStyleSheet("color: #e5e7eb; background-color: #0a1222; "
                                  "border: 1px solid #334155; border-radius: 10px; padding-left: 8px;")
        self.go_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

    def on_encrypt_error(self, message):
        self.status.setText(message)
        self.status.setStyleSheet("color: #ef4444; background-color: #0a1222; "
                                  "border: 1px solid #334155; border-radius: 10px; padding-left: 8px;")
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


class SharingPage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.owner_id = None
        self.setObjectName("SharingPage")

        # ===== Root (no outer margins; ContentWrap already has padding) =====
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        # ===== Card =====
        card = QFrame(objectName="Card")
        card.setFrameShape(QFrame.NoFrame)

        # optional shadow
        try:
            shadow = QGraphicsDropShadowEffect(self)
            shadow.setBlurRadius(32)
            shadow.setOffset(0, 12)
            shadow.setColor(QColor(0, 0, 0, 110))
            card.setGraphicsEffect(shadow)
        except Exception:
            pass

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 20, 20)
        card_layout.setSpacing(14)

        # ===== Title =====
        title = QLabel("🔗 Share Files", objectName="Title")
        subtitle = QLabel("Grant and revoke access to your encrypted files.", objectName="Subtitle")
        subtitle.setWordWrap(True)
        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)

        # Divider
        div1 = QFrame(); div1.setFrameShape(QFrame.HLine); div1.setObjectName("Divider")
        card_layout.addWidget(div1)

        # ===== Select file row =====
        top = QHBoxLayout()
        top.setSpacing(10)
        lab_files = QLabel("Your Files:", objectName="FieldLabel")
        self.file_combo = QComboBox()
        self.file_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        refresh_btn = QPushButton("Refresh", objectName="Secondary")
        refresh_btn.clicked.connect(self.refresh_files)
        top.addWidget(lab_files)
        top.addWidget(self.file_combo, 1)
        top.addWidget(refresh_btn)
        card_layout.addLayout(top)

        # ===== Recipient row =====
        rec_row = QHBoxLayout()
        rec_row.setSpacing(10)
        rec_row.addWidget(QLabel("Recipient (email/username):", objectName="FieldLabel"))
        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("alice@example.com or alice")
        rec_row.addWidget(self.recipient_input, 1)
        share_btn = QPushButton("Share", objectName="Primary")
        share_btn.clicked.connect(self.handle_share)
        rec_row.addWidget(share_btn)
        card_layout.addLayout(rec_row)

        # Divider
        div2 = QFrame(); div2.setFrameShape(QFrame.HLine); div2.setObjectName("Divider")
        card_layout.addWidget(div2)

        # ===== Current shares table =====
        lab_tbl = QLabel("Current Shares", objectName="SectionTitle")
        card_layout.addWidget(lab_tbl)

        self.table = QTableWidget(0, 3)
        self.table.setObjectName("SharesTable")
        self.table.setHorizontalHeaderLabels(["Recipient", "Shared At", "Actions"])
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(240)

        self.table.setTextElideMode(Qt.ElideNone)
        self.table.setWordWrap(True)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)           # Recipient
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)           # Shared At
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents) 

        card_layout.addWidget(self.table)

        root.addWidget(card, 1)

        # keep your original signal
        self.file_combo.currentIndexChanged.connect(self.refresh_shares)

        # ===== Scoped stylesheet =====
        self.setStyleSheet("""
        #SharingPage {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #0f172a, stop:1 #111827);
            color: #e5e7eb;
            font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif;
        }
        #SharingPage #Card {
            background: #0b1220;
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 18px;
        }
        #SharingPage QLabel#Title {
            font-size: 20px;
            font-weight: 600;
            color: #e5e7eb;
        }
        #SharingPage QLabel#Subtitle {
            color: #9fb0c7;
            font-size: 13px;
            margin-top: -2px;
            margin-bottom: 2px;
        }
        #SharingPage #Divider {
            background: #1e293b;
            min-height: 1px;
        }
        #SharingPage QLabel#FieldLabel {
            color: #cbd5e1;
            min-width: 170px;
        }
        #SharingPage QLabel#SectionTitle {
            color: #cbd5e1;
            font-size: 13px;
            letter-spacing: .2px;
            margin-top: 2px;
        }

        /* Inputs */
        #SharingPage QLineEdit, #SharingPage QComboBox {
            background: #0a1222;
            color: #e5e7eb;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 10px 12px;
        }
        #SharingPage QLineEdit:focus, #SharingPage QComboBox:focus {
            border: 1px solid #64748b;
        }
        #SharingPage QComboBox QAbstractItemView {
            background: #0a1222;
            color: #e5e7eb;
            selection-background-color: #111b2e;
            border: 1px solid #334155;
        }

        /* Buttons */
        #SharingPage QPushButton#Primary {
            background: #2563eb; color: white; font-weight: 600;
            border: none; border-radius: 12px; padding: 10px 14px;
        }
        #SharingPage QPushButton#Primary:hover { background: #1d4ed8; }
        #SharingPage QPushButton#Primary:pressed { background: #1e40af; }

        #SharingPage QPushButton#Secondary {
            background: #0a1222; color: #cbd5e1; font-weight: 600;
            border: 1px solid #334155; border-radius: 12px; padding: 10px 14px;
        }
        #SharingPage QPushButton#Secondary:hover { background: #0d1629; }

        #SharingPage QPushButton#DangerSmall {
            background: #ef4444; color: #ffffff; font-weight: 700;
            border: none; border-radius: 10px; padding: 6px 10px;
        }
        #SharingPage QPushButton#DangerSmall:hover { background: #dc2626; }
        #SharingPage QPushButton#DangerSmall:pressed { background: #b91c1c; }

        /* Table */
        #SharingPage QTableWidget#SharesTable {
            background: #111b2e;
            color: #e5e7eb;
            border: 1px solid #334155;
            border-radius: 12px;
            gridline-color: #1e293b;
            alternate-background-color: #0c1426;
            selection-background-color: #6d7178;
            selection-color: #e5e7eb;
        }
        #SharingPage QHeaderView::section {
            background: #0f1a2e;
            color: #cbd5e1;
            padding: 8px 10px;
            border: none;
            border-bottom: 1px solid #334155;
        }
        #SharingPage QTableCornerButton::section {
            background: #0f1a2e;
            border: none;
        }
        """)

    # =================== Existing logic (unchanged) ===================

    def showEvent(self, event):
        super().showEvent(event)
        if self.parent.current_user:
            self.owner_id = get_user_id(self.parent.current_user)
        self.refresh_files()

    def refresh_files(self):
        self.file_combo.clear()
        if not self.owner_id:
            return
        files = list_user_files(self.owner_id) or []
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
            # cells
            self.table.setItem(r, 0, QTableWidgetItem(recipient_handle or str(recipient_id)))
            self.table.setItem(r, 1, QTableWidgetItem(str(shared_at) if shared_at else ""))

            # Revoke button (styled)
            btn = QPushButton("Revoke")
            btn.setObjectName("DangerSmall")
            btn.clicked.connect(lambda _, rid=recipient_id, fid=file_id: self.handle_revoke(fid, rid))
            self.table.setCellWidget(r, 2, btn)
            self.table.setRowHeight(r, 36)
            self.table.resizeRowsToContents()

    def prompt_rsa_passphrase(self):
        dlg = QInputDialog(self)
        dlg.setWindowTitle("RSA Passphrase Required")
        dlg.setLabelText("Enter your RSA passphrase:")
        dlg.setInputMode(QInputDialog.TextInput)
        dlg.setTextEchoMode(QLineEdit.Password)
        dlg.setOkButtonText("OK")
        dlg.setCancelButtonText("Cancel")

        # Light look just for this dialog
        dlg.setStyleSheet("""
            QInputDialog { background: #ffffff; }
            QInputDialog QLabel { color: #111827; }
            QInputDialog QLineEdit {
                background: #ffffff; color: #111827;
                border: 1px solid #d1d5db; border-radius: 6px; padding: 6px 8px;
            }
            QInputDialog QPushButton { color: #111827; }
        """)

        if dlg.exec_() == QDialog.Accepted:
            val = dlg.textValue().strip()
            if val:
                return val

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
            # 1) Owner's encrypted session key
            owner_enc_blob = get_owner_enc_session_key(file_id)
            if not owner_enc_blob:
                QMessageBox.warning(self, "Missing key",
                    "Owner session key not found. You need to save it during encryption. Tell me if you want me to add that.")
                return

            # 2) Decrypt with owner's private key
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

            # 3) Encrypt session key for recipient
            recip_id = get_user_id(recipient_identifier)
            recip_pub_pem = get_user_public_key(recipient_identifier)
            if not recip_id or not recip_pub_pem:
                QMessageBox.warning(self, "Not found", "Recipient not found or missing public key.")
                return
            recip_pub = RSA.import_key(recip_pub_pem)
            enc_for_recipient = PKCS1_OAEP.new(recip_pub).encrypt(session_key)

            # 4) Store share
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




class ProfilePage(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.setObjectName("ProfilePage")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        card = QFrame(objectName="Card")
        card.setFrameShape(QFrame.NoFrame)

        try:
            shadow = QGraphicsDropShadowEffect(self)
            shadow.setBlurRadius(32)
            shadow.setOffset(0, 12)
            shadow.setColor(QColor(0, 0, 0, 110))
            card.setGraphicsEffect(shadow)
        except Exception:
            pass

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 20, 20)
        card_layout.setSpacing(14)

        # ----- Header: bigger round avatar + title -----
        header = QHBoxLayout()
        header.setSpacing(0)

        header_texts = QVBoxLayout()
        header_texts.setSpacing(0)
        self.title = QLabel("👤 User Profile", objectName="Title")
        subtitle = QLabel("Manage your account and cloud connection.", objectName="Subtitle")
        subtitle.setWordWrap(True)
        header_texts.addWidget(self.title)
        header_texts.addWidget(subtitle)

        self.avatar = QFrame(objectName="Avatar")
        self.avatar.setFixedSize(80, 80)  # bigger
        avl = QVBoxLayout(self.avatar)
        avl.setContentsMargins(0, 0, 0, 0)
        avl.setSpacing(120)
        self.avatar_label = QLabel("TS", self.avatar)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        avl.addWidget(self.avatar_label)

        header.addWidget(self.avatar)
        header.addLayout(header_texts)
        #header.addStretch(1)
        card_layout.addLayout(header)

        line1 = QFrame(); line1.setFrameShape(QFrame.HLine); line1.setObjectName("Divider")
        card_layout.addWidget(line1)

        # ----- Google Drive status + actions -----
        gdrive_row = QHBoxLayout()
        gdrive_row.setSpacing(1)

        self.gdrive_status = QLabel("Google Drive: Not connected", objectName="StatusChip")
        self.gdrive_status.setProperty("state", "disconnected")

        self.connect_btn = QPushButton("Connect Google Drive", objectName="Primary")
        self.disconnect_btn = QPushButton("Disconnect", objectName="Secondary")
        self.disconnect_btn.setEnabled(False)

        self.connect_btn.clicked.connect(self.connect_gdrive)
        self.disconnect_btn.clicked.connect(self.disconnect_gdrive)

        gdrive_row.addWidget(self.gdrive_status, 1)
        gdrive_row.addStretch(1)
        gdrive_row.addWidget(self.connect_btn)
        gdrive_row.addSpacing(12) 
        gdrive_row.addWidget(self.disconnect_btn)
        card_layout.addLayout(gdrive_row)

        line2 = QFrame(); line2.setFrameShape(QFrame.HLine); line2.setObjectName("Divider")
        card_layout.addWidget(line2)

        # ----- Account info (reuse your labels) -----
        info = QVBoxLayout()
        info.setSpacing(8)

        self.email_label = QLabel("Email: ", objectName="KV")
        self.username_label = QLabel("Username: ", objectName="KV")
        self.subcription_label = QLabel("Subcription Tier: ", objectName="KV")
        self.max_size_label = QLabel("Max file size: ", objectName="KV")

        info.addWidget(self.email_label)
        info.addWidget(self.username_label)
        info.addWidget(self.subcription_label)
        info.addWidget(self.max_size_label)
        card_layout.addLayout(info)

        # ----- Actions -----
        actions = QHBoxLayout()
        actions.addStretch(1)
        self.change_pass_btn = QPushButton("Change Password", objectName="Ghost")
        self.change_pass_btn.clicked.connect(self.show_change_password_dialog)
        actions.addWidget(self.change_pass_btn)
        card_layout.addLayout(actions)

        logout_row = QHBoxLayout()
        logout_row.addStretch(1)
        logout_btn = QPushButton("Log Out", objectName="Danger")
        logout_btn.clicked.connect(self.logout_user)
        logout_row.addWidget(logout_btn)
        logout_row.addStretch(1)
        card_layout.addLayout(logout_row)

        root.addWidget(card, 1)

        # Initial button text if already connected
        if getattr(self.parent, "google_drive_connected", False):
            self.connect_btn.setText("Connected")
            self.connect_btn.setEnabled(False)
            

        # ----- Scoped stylesheet -----
        self.setStyleSheet("""
        #ProfilePage {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #0f172a, stop:1 #111827);
            color: #e5e7eb;
            font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif;
        }
        #ProfilePage #Card {
            background: #0b1220;
            border: 1px solid rgba(255,255,255,0.06);
            font-size: 20px;
            border-radius: 18px;
        }
        #ProfilePage QLabel#Title {
            font-size: 20px;
            font-weight: 600;
            color: #e5e7eb;
        }
        #ProfilePage QLabel#Subtitle {
            color: #9fb0c7;
            font-size: 13px;
            margin-top: -2px;
        }
        #ProfilePage #Divider {
            background: #1e293b;
            min-height: 1px;
        }

        
        #ProfilePage #Avatar {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #1f2937, stop:1 #111827);
            border-radius: 999px;              
            border: 1px solid #263449;
        }
        #ProfilePage #Avatar QLabel {
            color: #cbd5e1;
            font-weight: 800;
            font-size: 26px;                   
            letter-spacing: 1px;
        }

        /* GDrive chip with dynamic states */
        #ProfilePage QLabel#StatusChip {
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid #334155;
            background: #0a1222;
            color: #cbd5e1;
            min-height: 24px;
        }
        #ProfilePage QLabel#StatusChip[state="connected"] {
            background: #dcfce7;
            border-color: #86efac;
            color: #14532d;
        }
        #ProfilePage QLabel#StatusChip[state="disconnected"] {
            background: #fee2e2;
            border-color: #fca5a5;
            color: #7f1d1d;
        }

        /* KV rows */
        #ProfilePage QLabel#KV {
            background: #0a1222;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 10px 12px;
            color: #e5e7eb;
        }

        /* Buttons */
        #ProfilePage QPushButton#Primary {
            background: #2563eb; color: white; font-weight: 600;
            border: none; border-radius: 12px; padding: 10px 14px;
        }
        #ProfilePage QPushButton#Primary:hover { background: #1d4ed8; }
        #ProfilePage QPushButton#Primary:pressed { background: #1e40af; }

        #ProfilePage QPushButton#Secondary {
            background: #0a1222; color: #cbd5e1; font-weight: 600;
            border: 1px solid #334155; border-radius: 12px; padding: 10px 14px;
        }
        #ProfilePage QPushButton#Secondary:hover { background: #0d1629; }

        #ProfilePage QPushButton#Ghost {
            background: transparent; color: #cbd5e1; font-weight: 600;
            border: 1px dashed #334155; border-radius: 12px; padding: 10px 14px;
        }
        #ProfilePage QPushButton#Ghost:hover { background: rgba(148,163,184,0.08); }

        #ProfilePage QPushButton#Danger {
            background: #ef4444; color: #ffffff; font-weight: 700;
            border: none; border-radius: 12px; padding: 10px 18px;
        }
        #ProfilePage QPushButton#Danger:hover { background: #dc2626; }
        #ProfilePage QPushButton#Danger:pressed { background: #b91c1c; }
        """)

    # ---------------- Existing logic (with tiny button text tweaks) ----------------

    def set_user_info(self, email, username):
        self.email_label.setText(f"Email: {email}")
        self.username_label.setText(f"Username: {username}")
        self.subcription_label.setText(f"Subcription Tier: {self.parent.user_subscription_tier}")
        self.max_size_label.setText(f"Max upload size: {format_file_size(self.parent.user_max_file_size)}")

        # Avatar initials
        initials = "TS"
        try:
            if username:
                parts = [p for p in username.replace("_", " ").split() if p]
                if len(parts) >= 2:
                    initials = (parts[0][0] + parts[1][0]).upper()
                else:
                    initials = parts[0][0:2].upper()
            elif email:
                initials = email.split("@", 1)[0][:2].upper()
        except Exception:
            pass
        self.avatar_label.setText(initials)

        # Determine Drive connection via meta file (your original behavior)
        vault = user_vault_dir(email)
        meta_file = _meta_path(vault)
        if os.path.isfile(meta_file):
            import json
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            gemail = meta.get("email", "")
            self.gdrive_status.setText(f"Google Drive Connected as {gemail or '(unknown)'}")
            self.gdrive_status.setProperty("state", "connected")
            self.gdrive_status.style().unpolish(self.gdrive_status)
            self.gdrive_status.style().polish(self.gdrive_status)
            self.disconnect_btn.setEnabled(True)
            self.connect_btn.setEnabled(False)
            self.connect_btn.setText("Connected")  # <-- update text
        else:
            self.gdrive_status.setText("Google Drive: Not connected")
            self.gdrive_status.setProperty("state", "disconnected")
            self.gdrive_status.style().unpolish(self.gdrive_status)
            self.gdrive_status.style().polish(self.gdrive_status)
            self.disconnect_btn.setEnabled(False)
            self.connect_btn.setEnabled(True)
            self.connect_btn.setText("Connect Google Drive")

        # Also reflect parent state, if already set
        if getattr(self.parent, "google_drive_connected", False):
            self.connect_btn.setText("Connected")
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)

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

        success, message = update_password(self.parent.current_user, old_pass, new_pass)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Error", message)

    def connect_gdrive(self):
        user = self.parent.current_user or ""
        if not user:
            QMessageBox.warning(self, "Google Drive", "Please log in first.")
            return
        try:
            vault = user_vault_dir(user)
            creds = get_credentials(vault)
            if not creds or not creds.valid:
                QMessageBox.warning(self, "Google Drive", "Could not obtain credentials.")
                return

            google_email, google_sub = get_google_identity(creds)
            service = build_drive(creds)
            ensure_trustshield_folder(service)

            
            _save_meta(vault, {"email": google_email, "sub": google_sub})

            self.gdrive_status.setText(f"Google Drive Connected as {google_email or '(unknown)'}")
            self.gdrive_status.setProperty("state", "connected")
            self.gdrive_status.style().unpolish(self.gdrive_status)
            self.gdrive_status.style().polish(self.gdrive_status)

            self.disconnect_btn.setEnabled(True)
            self.connect_btn.setEnabled(False)
            self.connect_btn.setText("Connected")  # <-- update text
            QMessageBox.information(self, "Google Drive", f"Connected as {google_email or google_sub}.")

            ok, _, _ = ensure_valid_credentials(user_vault_dir(self.parent.current_user), interactive=False)
            self.parent.google_drive_connected = ok

        except Exception as e:
            QMessageBox.warning(self, "Google Drive", f"Failed to connect: {e}")

    def disconnect_gdrive(self):
        try:
            vault = user_vault_dir(self.parent.current_user or "")
            disconnect_google(vault)
            self.gdrive_status.setText("Google Drive: Not connected")
            self.gdrive_status.setProperty("state", "disconnected")
            self.gdrive_status.style().unpolish(self.gdrive_status)
            self.gdrive_status.style().polish(self.gdrive_status)

            self.disconnect_btn.setEnabled(False)
            self.connect_btn.setEnabled(True)
            self.connect_btn.setText("Connect Google Drive")  # <-- back to default
            QMessageBox.information(self, "Google Drive", "Disconnected.")
            self.parent.google_drive_connected = False
        except Exception as e:
            QMessageBox.warning(self, "Google Drive", f"Failed to disconnect: {e}")

    def logout_user(self):
        confirm = QMessageBox.question(
            self, "Confirm Logout",
            "Are you sure you want to log out?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            self.parent.current_user = None
            self.parent.user_subscription_tier = None
            self.parent.user_max_file_size = None
            self.parent.google_drive_connected = False
            self.connect_btn.setEnabled(True)
            self.connect_btn.setText("Connect Google Drive")
            self.parent.update_nav_visibility(0)


class DecryptPageV2(QWidget):

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.selected_fragments = []
        self.setObjectName("DecryptV2")

        # ===== Root (no extra outer margins; ContentWrap already has padding) =====
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        # ===== Card =====
        card = QFrame(objectName="Card")
        card.setFrameShape(QFrame.NoFrame)

        # soft shadow (optional)
        try:
            eff = QGraphicsDropShadowEffect(self)
            eff.setBlurRadius(32)
            eff.setOffset(0, 12)
            eff.setColor(QColor(0, 0, 0, 110))
            card.setGraphicsEffect(eff)
        except Exception:
            pass

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 20, 20)
        card_layout.setSpacing(14)

        # ===== Title =====
        title = QLabel("🧩 Decrypt & Reconstruct", objectName="Title")
        subtitle = QLabel("Fetch shards from Drive or add local fragments to reconstruct files.", objectName="Subtitle")
        subtitle.setWordWrap(True)
        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)

        # Divider
        div0 = QFrame(); div0.setFrameShape(QFrame.HLine); div0.setObjectName("Divider")
        card_layout.addWidget(div0)

        # ===== Output folder =====
        out_row = QHBoxLayout()
        out_row.setSpacing(10)

        out_row.addWidget(QLabel("Decrypted File Folder:", objectName="FieldLabel"))
        self.output_folder = QLineEdit()
        self.output_folder.setPlaceholderText("Select output folder for decrypted file")
        self.output_folder.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        out_btn = QPushButton("Browse Output", objectName="Secondary")
        out_btn.clicked.connect(self._browse_output)

        out_row.addWidget(self.output_folder, 1)
        out_row.addWidget(out_btn)
        card_layout.addLayout(out_row)

        # ===== Password row =====

        pass_row = QHBoxLayout()
        pass_row.setSpacing(10)

        pass_row.addWidget(QLabel("Your RSA Password:", objectName="FieldLabel"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Your RSA password")
        self.password_input.setMinimumWidth(220)
        pass_row.addWidget(self.password_input)

        pass_row.addStretch(1)  # pushes the next widget to the right

        self.view_output_btn = QPushButton("View output", objectName="Secondary")
        
        self.view_output_btn.setToolTip("Open the output folder in your file manager")
        self.view_output_btn.clicked.connect(self.view_output_folder)
        pass_row.addWidget(self.view_output_btn, 0, Qt.AlignRight)

        card_layout.addLayout(pass_row)

        # ===== My files =====
        

        card_layout.addWidget(self._line())

        # --- "My files" header row with right-aligned Recover button ---
        my_header = QHBoxLayout()
        my_header.setContentsMargins(0, 0, 0, 0)
        my_header.setSpacing(10)

        lbl_my = QLabel("My files", objectName="SectionTitle")
        my_header.addWidget(lbl_my)
        my_header.addStretch(1)

        self.recover_btn = QPushButton("Recover fragments", objectName="Primary")
        self.recover_btn.setFixedHeight(30)
        self.recover_btn.setFixedWidth(170)
        self.recover_btn.setToolTip("Recover missing fragments from your recovery vault and database.")
        self.recover_btn.clicked.connect(self.recover_fragments_flow)

        my_header.addWidget(self.recover_btn, 0, Qt.AlignRight)
        card_layout.addLayout(my_header)

        self.my_tbl = QTableWidget(0, 3)
        self.my_tbl.setHorizontalHeaderLabels(["Filename", "File ID", "Actions"])
        card_layout.addWidget(self.my_tbl)
        self._setup_table(self.my_tbl)
        

        # ===== Shared with me =====
        card_layout.addWidget(self._line())
        card_layout.addWidget(QLabel("Shared with me", objectName="SectionTitle"))

        self.shared_tbl = QTableWidget(0, 3)
        self.shared_tbl.setHorizontalHeaderLabels(["Filename", "File ID", "Actions"])
        card_layout.addWidget(self.shared_tbl)
        self._setup_table(self.shared_tbl)


        # ===== Progress + status =====
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFormat("%p% - %v/%m")
        self.progress_bar.setFixedHeight(22)
        card_layout.addWidget(self.progress_bar)

        self.status = QLabel("Status:", objectName="StatusBar")
        self.status.setMinimumHeight(34)
        self.status.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card_layout.addWidget(self.status)

        root.addWidget(card, 1)

        # ===== Scoped stylesheet (DecryptV2 only) =====
        self.setStyleSheet("""
        #DecryptV2 {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #0f172a, stop:1 #111827);
            color: #e5e7eb;
            font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif;
        }
        #DecryptV2 #Card {
            background: #0b1220;
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 18px;
        }
        #DecryptV2 QLabel#Title {
            font-size: 20px;
            font-weight: 600;
            color: #e5e7eb;
        }
        #DecryptV2 QLabel#Subtitle {
            color: #9fb0c7;
            font-size: 13px;
            margin-top: -2px;
            margin-bottom: 2px;
        }
        #DecryptV2 #Divider { background: #1e293b; min-height: 1px; }

        #DecryptV2 QLabel#FieldLabel { color: #cbd5e1; min-width: 190px; }
        #DecryptV2 QLabel#SectionTitle { color: #cbd5e1; font-size: 13px; letter-spacing: .2px; }

        #DecryptV2 QLineEdit {
            background: #0a1222;
            color: #e5e7eb;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 10px 12px;
        }
        #DecryptV2 QLineEdit:focus { border: 1px solid #64748b; }

        /* Buttons */
        #DecryptV2 QPushButton#Primary {
            background: #2563eb; color: white; font-weight: 600;
            border: none; border-radius: 12px; padding: 10px 14px;
        }
        #DecryptV2 QPushButton#Primary:hover { background: #1d4ed8; }
        #DecryptV2 QPushButton#Primary:pressed { background: #1e40af; }

        #DecryptV2 QPushButton#Secondary {
            background: #0a1222; color: #cbd5e1; font-weight: 600;
            border: 1px solid #334155; border-radius: 12px; padding: 10px 14px;
        }
        #DecryptV2 QPushButton#Secondary:hover { background: #0d1629; }

        #DecryptV2 QPushButton#Tiny {
            background: #2563eb; color: #ffffff; font-weight: 700;
            border: none; border-radius: 8px; padding: 4px 10px;
            font-size: 12px; min-width: 0; min-height: 0;
        }
        #DecryptV2 QPushButton#Tiny:hover { background: #1d4ed8; }
        #DecryptV2 QPushButton#Tiny:pressed { background: #1e40af; }

        #DecryptV2 QPushButton#DangerTiny {
            background: #ef4444; color: #ffffff; font-weight: 700;
            border: none; border-radius: 8px; padding: 4px 10px;
            font-size: 12px; min-width: 0; min-height: 0;
        }
        #DecryptV2 QPushButton#DangerTiny:hover { background: #dc2626; }
        #DecryptV2 QPushButton#DangerTiny:pressed { background: #b91c1c; }

        /* Tables */
        #DecryptV2 QTableWidget {
            background: #111b2e;
            color: #e5e7eb;
            border: 1px solid #334155;
            border-radius: 12px;
            gridline-color: #1e293b;
            alternate-background-color: #0c1426;
            selection-background-color: #6d7178;
            selection-color: #e5e7eb;
        }

        #DecryptV2 QHeaderView::section {
            background: #0f1a2e;
            color: #cbd5e1;
            padding: 8px 10px;
            border: none;
            border-bottom: 1px solid #334155;
        }
        #DecryptV2 QTableCornerButton::section { background: #0f1a2e; border: none; }

        /* Progress + status */
        #DecryptV2 QProgressBar {
            background: #0a1222;
            border: 1px solid #334155;
            border-radius: 10px;
            text-align: center;
            height: 22px;
        }
        #DecryptV2 QProgressBar::chunk {
            border-radius: 10px;
            margin: 1px;
            background-color: #2563eb;
        }
        #DecryptV2 QLabel#StatusBar {
            background: #0a1222;
            border: 1px solid #334155;
            border-radius: 10px;
            padding-left: 8px;
            color: #e5e7eb;
        }
        """)

    # ---------- helpers: visuals for tables ----------
    def _setup_table(self, table: QTableWidget):
        """Apply consistent sizing so text doesn't get clipped and actions stay compact."""
        table.setAlternatingRowColors(True)
        table.setShowGrid(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.setMinimumHeight(240)

        # Don't elide; allow wrapping; size rows to contents (prevents clipping)
        table.setTextElideMode(Qt.ElideNone)
        table.setWordWrap(True)
        table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        # Columns: Filename (stretch), File ID (stretch), Actions (content)
        hdr = table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.Interactive)
        table.setColumnWidth(2, 320)

        # center the "Actions" header title
        item = table.horizontalHeaderItem(2)
        if item:
            item.setTextAlignment(Qt.AlignCenter)

    def _line(self):
        ln = QFrame()
        ln.setFrameShape(QFrame.HLine)
        ln.setFrameShadow(QFrame.Sunken)
        ln.setObjectName("Divider")
        return ln

    # ---------- lifecycle ----------
    def showEvent(self, ev):
        super().showEvent(ev)
        self._reload_lists()

    # ---------- Data loading ----------
    def _reload_lists(self):
        """Populate 'My files' and 'Shared with me' from DB."""
        self._load_my_files()
        self._load_shared_with_me()

    def _load_my_files(self):
        self.my_tbl.setRowCount(0)
        email = self.parent.current_user
        if not email:
            return
        owner_id = get_user_id(email)
        rows = list_user_files(owner_id) or []
        for (fid, fname) in rows:
            self._insert_row(self.my_tbl, fname, fid, allow_delete=True)   # ← keep delete

    def _load_shared_with_me(self):
        self.shared_tbl.setRowCount(0)
        email = self.parent.current_user
        if not email:
            return
        uid = get_user_id(email)
        files = self._db_list_shared_with_user(uid)
        for (fid, fname) in files:
            self._insert_row(self.shared_tbl, fname, fid, allow_delete=False)  # ← no delete

    def _db_list_shared_with_user(self, recipient_id):
        """Return list of (file_uuid, filename) that were shared with this user."""
        conn, cur = get_connection()
        if not conn:
            return []
        try:
            cur.execute("""
                SELECT nf.file_uuid, nf.filename
                FROM file_shares fs
                JOIN newfiles nf ON nf.file_uuid = fs.file_id
                WHERE fs.recipient_id = %s
                ORDER BY fs.shared_at DESC
            """, (recipient_id,))
            return cur.fetchall() or []
        finally:
            cur.close(); conn.close()

    def _insert_row(self, table, filename, file_id, allow_delete: bool = True):
        r = table.rowCount()
        table.insertRow(r)

        it_name = QTableWidgetItem(filename or "")
        it_name.setToolTip(it_name.text())
        table.setItem(r, 0, it_name)

        it_id = QTableWidgetItem(file_id or "")
        it_id.setToolTip(it_id.text())
        table.setItem(r, 1, it_id)

        # Actions cell (centered)
        actions = QWidget()
        hl = QHBoxLayout(actions)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.setSpacing(8)
        hl.setAlignment(Qt.AlignCenter)

        fetch_btn = QPushButton("Reconstruct and Decrypt")
        fetch_btn.setObjectName("Tiny")
        fetch_btn.setFixedHeight(24)
        fetch_btn.clicked.connect(lambda _, fid=file_id, fname=filename: self._fetch_then_reconstruct(fid, fname))
        hl.addWidget(fetch_btn)

        if allow_delete:
            del_btn = QPushButton("Delete")
            del_btn.setObjectName("DangerTiny")
            del_btn.setFixedHeight(24)
            del_btn.setToolTip("Delete DB record, Drive fragments, recovery vault, and local copies (if found).")
            del_btn.clicked.connect(lambda _, fid=file_id, fname=filename: self._confirm_and_delete(fid, fname))
            hl.addWidget(del_btn)

        table.setCellWidget(r, 2, actions)

        # Let row height adapt to wrapped text
        table.setRowHeight(r, max(28, table.rowHeight(r)))
        table.resizeRowToContents(r)

    # ---------- Drive fetch + reconstruct ----------
    def _fetch_then_reconstruct(self, file_id, filename):
        """Download fragments from Drive/<TrustShield>/<file_id>, and if < k, prompt for local fragments."""
        passwd = self.password_input.text().strip()
        if not passwd:
            QMessageBox.warning(self, "Missing password", "Please enter your RSA password.")
            return
        out_dir = self.output_folder.text().strip()
        if not out_dir or not os.path.isdir(out_dir):
            QMessageBox.warning(self, "Output folder", "Please select a valid output folder.")
            return

        k = self._db_get_required_k(file_id)
        if k is None:
            k = 3  # fallback

        email = self.parent.current_user or ""
        ok, creds, _ = ensure_valid_credentials(user_vault_dir(email), interactive=False)

        if not ok or not creds:
            downloaded_paths = self._fetch_without_google(file_id, out_dir, k)
            if not downloaded_paths:
                QMessageBox.information(
                    self, "Google Drive",
                    "No Drive fragments available to fetch without Google login.\n"
                    "Please add fragments from local disk."
                )
            self._prompt_local_and_reconstruct(downloaded_paths, k, out_dir, passwd, file_id)
            return

        try:
            service = build_drive(creds)
            folder_id = ensure_trustshield_subfolder(service, file_id)

            frags = list_fragments_in_folder(service, folder_id)
            if not frags:
                QMessageBox.information(self, "Google Drive", "No fragments found in Drive for this file.")
                self._prompt_local_and_reconstruct([], k, out_dir, passwd,file_id)
                return

            temp_frag_dir = os.path.join(out_dir, f"{file_id}_fragments")
            os.makedirs(temp_frag_dir, exist_ok=True)

            self._set_busy(True, "Downloading fragments from Google Drive...")
            downloaded_paths = []
            total = len(frags)
            for i, item in enumerate(frags, 1):
                local = os.path.join(temp_frag_dir, item["name"])
                download_file_to(service, item["id"], local)
                downloaded_paths.append(local)
                self.progress_bar.setVisible(True)
                self.progress_bar.setValue(int(30 * i / max(1, total)))
                self.status.setText(f"Downloading: {i}/{total}")

            self._prompt_local_and_reconstruct(downloaded_paths, k, out_dir, passwd, file_id)

        except Exception as e:
            self._set_busy(False)
            QMessageBox.critical(self, "Google Drive", f"Download failed: {e}")

    def _prompt_local_and_reconstruct(self, existing_paths, k, out_dir, passwd, file_id):
        """If we have < k, prompt to add local fragments until >= k or user cancels, then reconstruct."""
        paths = list(existing_paths)
        have = len(paths)
        while have < k:
            needed = k - have
            resp = QMessageBox.question(
                self, "More fragments needed",
                f"You have {have}/{k} fragments.\n"
                f"Add at least {needed} more fragment(s) from local disk?",
                QMessageBox.Yes | QMessageBox.No
            )
            if resp != QMessageBox.Yes:
                self._set_busy(False)
                self.status.setText("Status: Not enough fragments to reconstruct.")
                return
            files, _ = QFileDialog.getOpenFileNames(self, f"Select Fragment Files: ({file_id})", filter="Fragment Files (*.frag)")
            if not files:
                continue
            for p in files:
                if p not in paths:
                    paths.append(p)
            have = len(paths)

        self._run_worker(paths, out_dir, passwd)

    # ---------- Worker plumbing ----------
    def _run_worker(self, frag_paths, out_dir, passwd):
        try:
            if not frag_paths:
                QMessageBox.warning(self, "No fragments", "No fragments to reconstruct.")
                self._set_busy(False)
                return

            self.progress_bar.setValue(35)
            self.status.setText("Starting reconstruction and decryption...")
            self.progress_bar.setVisible(True)

            self.worker = DecryptReconstructWorker(frag_paths, out_dir, passwd, self.parent.current_user)
            self.worker.finished.connect(self._on_finished)
            self.worker.error.connect(self._on_error)
            self.worker.progress.connect(self._on_progress)
            self.worker.start()
        except Exception as e:
            self._set_busy(False)
            QMessageBox.critical(self, "Error", str(e))

    def _on_progress(self, pct, msg):
        self.progress_bar.setValue(pct)
        self.status.setText(f"Status: {msg}")

    def _on_finished(self, msg):
        self.status.setText(f"Status: {msg}")
        self.status.setStyleSheet("color: black; background-color: #f0f0f0; padding-left: 5px;")
        self._set_busy(False)

    def _on_error(self, msg):
        self.status.setText(msg)
        self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
        self._set_busy(False)

    def _set_busy(self, busy, text=None):
        self.go_enabled = not busy
        self.progress_bar.setVisible(busy)
        if text:
            self.status.setText(text)

    # ---------- Small utils ----------
    def _browse_output(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output_folder.setText(folder)

    def _db_get_required_k(self, file_uuid):
        """Return required_shards (k) for file_uuid or None."""
        conn, cur = get_connection()
        if not conn:
            return None
        try:
            cur.execute(
                "SELECT required_shards FROM newfiles WHERE file_uuid=%s",
                (file_uuid,)
            )
            row = cur.fetchone()
            return int(row[0]) if row else None
        finally:
            cur.close(); conn.close()

    def _fetch_without_google(self, file_id, out_dir, k):
        rows = list_drive_fragments(file_id)  # [(idx, drive_file_id), ...]
        if not rows:
            return []

        temp_dir = os.path.join(out_dir, f"{file_id}_fragments")
        os.makedirs(temp_dir, exist_ok=True)

        downloaded = []
        for idx, dfid in rows:
            local = os.path.join(temp_dir, f"{file_id}_{idx}.frag")
            try:
                download_public_drive_file(dfid, local)
                downloaded.append(local)
            except Exception:
                pass
        return downloaded

    def _confirm_and_delete(self, file_id: str, filename: str):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Delete file and fragments?")
        msg.setText(f"Delete '{filename}' ({file_id}) everywhere?")
        msg.setInformativeText(
            "This will:\n"
            "• Remove the database record and sharing links\n"
            "• Delete Google Drive fragments (if linked)\n"
            "• Clear recovery-vault backups (if present)\n"
            "• Try to remove local fragments (if known)\n\n"
            "This action cannot be undone."
        )
        msg.setStandardButtons(QMessageBox.Cancel | QMessageBox.Yes)
        msg.setDefaultButton(QMessageBox.Cancel)
        if msg.exec_() != QMessageBox.Yes:
            return

        self._run_delete_worker(file_id, filename)

    def _run_delete_worker(self, file_uuid: str, filename: str):
        extra_paths = set()

        for root in getattr(self.parent, "known_fragment_roots", []):
            d = os.path.join(root, file_uuid)
            if os.path.isdir(d):
                extra_paths.add(d)

        out_dir = (self.output_folder.text() or "").strip()
        if out_dir:
            d1 = os.path.join(out_dir, file_uuid)
            d2 = os.path.join(out_dir, f"{file_uuid}_fragments")
            if os.path.exists(d1): extra_paths.add(d1)
            if os.path.exists(d2): extra_paths.add(d2)

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(5)
        self.status.setText("Deleting…")
        self._set_busy(True)

        self._del_worker = DeleteFileWorker(
            file_uuid=file_uuid,
            user_email=(self.parent.current_user or ""),
            extra_local_paths=list(extra_paths)
        )
        self._del_worker.progress.connect(self._on_delete_progress)
        self._del_worker.finished.connect(self._on_delete_finished)
        self._del_worker.error.connect(self._on_delete_error)
        self._del_worker.start()

    def _on_delete_progress(self, pct: int, msg: str):
        self.progress_bar.setValue(pct)
        self.status.setText(f"Status: {msg}")

    def _on_delete_finished(self, msg: str):
        self.status.setText(f"Status: {msg}")
        self.status.setStyleSheet("color: black; background-color: #f0f0f0; padding-left: 5px;")
        self._set_busy(False)
        self._reload_lists()

    def _on_delete_error(self, msg: str):
        self.status.setText(msg)
        self.status.setStyleSheet("color: red; background-color: #f0f0f0; padding-left: 5px;")
        self._set_busy(False)

    def recover_fragments_flow(self):
        email = self.parent.current_user or ""
        if not email:
            QMessageBox.warning(self, "Not logged in", "Please login first.")
            return

        out_dir = QFileDialog.getExistingDirectory(self, "Select folder to copy recovered fragments into")
        if not out_dir:
            return

        # 2FA (2 minutes, and resend resets the same timer in your TwoFADialog)
        code = generate_code()
        action = "recover file"
        print(f"The code for {action} is: {code}")

        self._email_thread = EmailSender(email, code, action, self)
        self._email_thread.start()

        def resend_code():
            new_code = generate_code()
            self._email_thread = EmailSender(email, new_code, action, self)
            self._email_thread.start()
            return new_code

        dialog = TwoFADialog(expected_code=code, resend_callback=resend_code, duration_seconds=120)
        if dialog.exec_() != QDialog.Accepted:
            return

        try:
            files = get_user_files(email)
            if not files:
                QMessageBox.information(self, "No files", "No files found for your account.")
                return

            # Choose file if multiple
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

            # UI busy state
            self._set_busy(True, "Recovering fragments from recovery vault and database…")
            self.recover_btn.setEnabled(False)

            # Perform recovery
            result = recover_missing_fragments(email, file_id, out_dir)

            # UI back to normal
            self._set_busy(False)
            self.recover_btn.setEnabled(True)

            if result.get("copied", 0) == 0 and result.get("have", 0) == 0:
                QMessageBox.information(self, "Recovery",
                    "No fragments could be recovered from DB or vault.")
                return

            msg = (
                f"Recovered {result.get('copied', 0)} fragment(s).\n"
                f"Now have {result.get('have', 0)} of {result.get('n', '?')} shards (k={result.get('k', '?')})."
            )
            missing = result.get("missing", 0)
            if missing > 0:
                msg += f"\nStill missing {missing} fragment(s)."

            QMessageBox.information(self, "Recovery complete", msg)

        except Exception as e:
            self._set_busy(False)
            self.recover_btn.setEnabled(True)
            QMessageBox.critical(self, "Recovery error", str(e))


    def view_output_folder(self):
        path = (self.output_folder.text() or "").strip()
        if not path or not os.path.isdir(path):
            QMessageBox.warning(self, "Output folder", "Please select a valid output folder first.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))