import sys
import os
import time
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QMainWindow, QStackedWidget,
    QLineEdit, QFileDialog, QStackedLayout, QFrame, QProgressBar,  QMessageBox, 
    QComboBox, QDialog, QInputDialog, QSizePolicy, QSpacerItem, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from uiPage import LoginPage, EncryptPage, DecryptPage, SharingPage, ProfilePage, RegisterPage, DecryptPageV2

class MainWindow(QMainWindow):
    def update_nav_visibility(self, index: int):
        # Show sidebar for app pages (>=2), hide for login/register
        if hasattr(self, "nav_widget"):
            self.nav_widget.setVisible(index >= 2)
        if hasattr(self, "stack"):
            self.stack.setCurrentIndex(index)
        self._mark_selected(index)

    def __init__(self):
        super().__init__()
        self.setObjectName("MainWindow")
        self.setWindowTitle("TrustShield - Secure File Encryptor")
        self.setMinimumSize(1000, 900)

        # ---- shared state
        self.current_user = None
        self.user_subscription_tier = None
        self.user_max_file_size = None
        self.google_drive_connected = False

        # ---- central widget
        cw = QWidget(self)
        self.setCentralWidget(cw)
        root = QHBoxLayout(cw)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # =====================================================================
        # Sidebar (left)
        # =====================================================================
        self.nav_widget = QFrame(objectName="Sidebar")
        self.nav_widget.setFixedWidth(200)
        nav_layout = QVBoxLayout(self.nav_widget)
        nav_layout.setContentsMargins(16, 18, 16, 18)
        nav_layout.setSpacing(10)

        brand = QLabel("🛡️ TrustShield", self.nav_widget)
        bf = QFont()
        bf.setPointSize(14)
        bf.setWeight(QFont.DemiBold)
        brand.setFont(bf)
        brand.setObjectName("Brand")
        nav_layout.addWidget(brand)

        sub = QLabel("Secure your files", self.nav_widget)
        sub.setObjectName("BrandSub")
        nav_layout.addWidget(sub)

        nav_layout.addSpacing(6)
        divider = QFrame(self.nav_widget)
        divider.setFrameShape(QFrame.HLine)
        divider.setObjectName("Divider")
        nav_layout.addWidget(divider)

        # Nav buttons (these map to your existing indices)
        self.btn_encrypt = QPushButton("🔒  Encrypt", self.nav_widget, objectName="NavBtn")
        self.btn_decrypt = QPushButton("🔓  Decrypt", self.nav_widget, objectName="NavBtn")
        self.btn_share   = QPushButton("📤  Share",   self.nav_widget, objectName="NavBtn")
        self.btn_profile = QPushButton("👤  Profile", self.nav_widget, objectName="NavBtn")

        for b in (self.btn_encrypt, self.btn_decrypt, self.btn_share, self.btn_profile):
            b.setCursor(Qt.PointingHandCursor)
            b.setFixedHeight(42)
            nav_layout.addWidget(b)

        nav_layout.addStretch(1)

        # =====================================================================
        # Stacked pages (right)
        # =====================================================================
        self.stack = QStackedWidget()

        # Instantiate pages (keep your existing classes & parents)
        self.login_page    = LoginPage(self)        # index 0
        self.register_page = RegisterPage(self)     # index 1
        self.encrypt_page  = EncryptPage(self)      # index 2
        self.decrypt_page  = DecryptPageV2(self)      # index 3
        self.sharing_page  = SharingPage(self)      # index 4
        self.profile_page  = ProfilePage(self)      # index 5

        # Add pages to stack
        self.stack.addWidget(self.login_page)       # 0
        self.stack.addWidget(self.register_page)    # 1
        self.stack.addWidget(self.encrypt_page)     # 2
        self.stack.addWidget(self.decrypt_page)     # 3
        self.stack.addWidget(self.sharing_page)     # 4
        self.stack.addWidget(self.profile_page)     # 5

        # =====================================================================
        # Wire up navigation
        # =====================================================================
        self._index_to_btn = {
            2: self.btn_encrypt,
            3: self.btn_decrypt,
            4: self.btn_share,
            5: self.btn_profile,
        }

        self.btn_encrypt.clicked.connect(lambda: self.update_nav_visibility(2))
        self.btn_decrypt.clicked.connect(lambda: self.update_nav_visibility(3))
        self.btn_share.clicked.connect(  lambda: self.update_nav_visibility(4))
        self.btn_profile.clicked.connect(lambda: self.update_nav_visibility(5))

        # =====================================================================
        # Assemble layout
        # =====================================================================
        root.addWidget(self.nav_widget)

        content_wrap = QFrame(objectName="ContentWrap")
        content_layout = QVBoxLayout(content_wrap)
        content_layout.setContentsMargins(24, 24, 24, 24)
        content_layout.setSpacing(0)
        content_layout.addWidget(self.stack)

        root.addWidget(content_wrap, 1)

        # Start on login (sidebar hidden)
        self.update_nav_visibility(0)

        # =====================================================================
        # Scoped styles
        # =====================================================================
        self.setStyleSheet("""
        #MainWindow {
            background: #0f172a;
            font-family: 'Segoe UI','Roboto','Helvetica','Arial',sans-serif;
            color: #e2e8f0;
        }

        /* Sidebar */
        #Sidebar {
            background: #0b1220;
            border-right: 1px solid #151c2b;
        }
        #Sidebar #Brand { color: #e5e7eb; }
        #Sidebar #BrandSub { color: #9fb0c7; font-size: 12px; margin-top: -4px; }
        #Sidebar #Divider { background: #1e293b; height: 1px; }

        QPushButton#NavBtn {
            text-align: left;
            padding: 10px 12px;
            border: 1px solid transparent;
            border-radius: 10px;
            color: #cbd5e1;
            background: transparent;
            font-weight: 600;
        }
        QPushButton#NavBtn:hover {
            background: rgba(148,163,184,0.08);
        }
        QPushButton#NavBtn[selected="true"] {
            background: #111b2e;
            border-color: #263449;
            color: #ffffff;
        }

        /* Right side content background */
        #ContentWrap {
            background: qlineargradient(x1:0,y1:0, x2:1,y2:1, stop:0 #0f172a, stop:1 #111827);
        }
        """)

    # Highlight the currently selected nav button
    def _mark_selected(self, index: int):
        if not hasattr(self, "_index_to_btn"):
            return
        for i, btn in self._index_to_btn.items():
            btn.setProperty("selected", i == index)
            btn.style().unpolish(btn)
            btn.style().polish(btn)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())