"""
Modern Qt (PySide6) Secure Chat Client
"""
import sys
import os
import json
import threading
import time
import base64
from queue import Queue

# --- Cryptography Imports ---
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions

# --- Networking ---
import requests

# --- Qt Imports ---
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QListWidget, QListWidgetItem,
    QTextEdit, QSplitter, QDialog, QMessageBox, QInputDialog, QFrame
)
from PySide6.QtCore import (
    Qt, QObject, Signal, Slot, QThread, QSize
)
from PySide6.QtGui import QIcon, QFont

# --- Configuration ---
CONFIG_FILE = 'client_config.json'
DEFAULT_HOMESERVER = 'http://127.0.0.1:5000'
# (2048 bits / 8) - (2 * 256 bits / 8) - 2 = 256 - 64 - 2 = 190 bytes
RSA_MAX_MESSAGE_BYTES = 190

# --- STYLING (QSS) ---
# A modern, "Tailwind-inspired" dark palette
GLOBAL_STYLESHEET = """
/* ---------- Base ---------- */
QWidget {
    background-color: #0f1724; /* deeper base */
    color: #e6eef8;            /* light text */
    font-family: "Inter", "Segoe UI", "Cantarell", "Noto Sans", sans-serif;
    font-size: 10.5pt;
    line-height: 1.4;
}

/* Use a subtle global gap for layouts (applies visually) */
QMainWindow, QWidget#root {
    padding: 0px;
}

/* ---------- Card container ---------- */
QFrame#card {
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(255,255,255,0.02),
        stop:1 rgba(255,255,255,0.01)
    );
    border: 1px solid rgba(255,255,255,0.04);
    border-radius: 12px;
    padding: 18px;
    margin: 6px;
}

/* ---------- Headings ---------- */
QLabel#heading {
    font-size: 18pt;
    font-weight: 600; /* semi-bold, not heavy */
    color: #d7b7ff; /* soft mauve accent */
    padding: 6px 0 12px 0;
    letter-spacing: 0.2px;
}
QLabel#subheading {
    font-size: 11pt;
    font-weight: 500;
    color: #9ec8ff;
    padding: 8px 0 6px 0;
}

/* Small helper labels (status, hints) */
QLabel#status {
    color: #ffb4c1; /* gentle alert pink */
    font-size: 9.5pt;
    padding: 4px 0;
}

/* ---------- Inputs ---------- */
QLineEdit, QTextEdit {
    background-color: rgba(255,255,255,0.02);
    border: 1px solid rgba(255,255,255,0.05);
    padding: 10px;
    border-radius: 8px;
    color: #e6eef8;
    selection-background-color: rgba(137,180,250,0.18);
    selection-color: #e6eef8;
    min-height: 30px;
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid rgba(137,180,250,0.9);
    outline: none;
}

/* Placeholder style (less bold, more subtle) */
QLineEdit[placeholderText="true"] {
    color: rgba(230,238,248,0.55);
}

/* ---------- Buttons (primary & ghost) ---------- */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                               stop:0 rgba(137,180,250,0.95),
                               stop:1 rgba(96,165,250,0.95));
    color: #071027;
    font-weight: 600;
    border-radius: 10px;
    padding: 8px 14px;
    min-height: 34px;
    border: none;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                               stop:0 rgba(147,190,250,0.95),
                               stop:1 rgba(106,175,250,0.95));
}
QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                               stop:0 rgba(96,165,250,0.95),
                               stop:1 rgba(137,180,250,0.95));
}

/* Secondary / ghost button */
QPushButton#secondary {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.06);
    color: #e6eef8;
    font-weight: 600;
}
QPushButton#secondary:hover {
    background: rgba(255,255,255,0.02);
}

/* Small link-style button */
QPushButton.link {
    background: transparent;
    color: #9ec8ff;
    border: none;
    padding: 6px;
    font-weight: 500;
}

/* ---------- Lists / Contacts / Requests ---------- */
QListWidget {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.03);
    border-radius: 8px;
    padding: 6px;
    outline: none;
}
QListWidget::item {
    padding: 10px 12px;
    margin: 4px 0;
    border-radius: 8px;
}
QListWidget::item:selected {
    background: rgba(137,180,250,0.12);
    color: #dff3ff;
}
QListWidget::item:hover {
    background: rgba(255,255,255,0.02);
}

/* Ensure items don't get clipped; allow multiline wrap */
QListWidget QLabel, QListWidgetItem {
    qproperty-sizeHint: 48px;
    text-align: left;
}

/* ---------- Chat display ---------- */
QTextEdit#chat_display {
    background: transparent;
    border: none;
    padding: 6px 8px;
    border-radius: 8px;
}

/* Message bubbles via HTML (we rely on your HTML colors) */
p { margin: 4px 0; padding: 6px 10px; border-radius: 8px; }

/* System messages smaller and muted */
p.system { color: rgba(230,238,248,0.6); font-style: italic; text-align: center; font-size: 9.6pt; }

/* ---------- Splitter handle ---------- */
QSplitter::handle {
    background: transparent;
}
QSplitter::handle:horizontal {
    width: 10px;
}

/* ---------- Scrollbars (thin, modern) ---------- */
QScrollBar:vertical {
    background: transparent;
    width: 9px;
}
QScrollBar::handle:vertical {
    background: rgba(255,255,255,0.06);
    min-height: 30px;
    border-radius: 6px;
}
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }

/* ---------- Buttons sizing helpers ---------- */
QPushButton#small {
    min-height: 28px;
    padding: 6px 10px;
    font-size: 9.6pt;
}

/* ---------- Misc ---------- */
QLabel, QPushButton, QLineEdit { color: #e6eef8; }
"""


# --- APIClient: Handles all server communication ---
# MODIFIED: Removed all tkinter.messagebox dependencies.
# The UI will be responsible for handling None responses.
class APIClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token

    def set_base_url(self, base_url):
        self.base_url = base_url

    def _get_headers(self):
        """Returns headers for authenticated requests."""
        if not self.token:
            return {'Content-Type': 'application/json'}
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }

    def _request(self, method, endpoint, data=None, params=None):
        """Helper for making API requests."""
        url = self.base_url + endpoint
        headers = self._get_headers()
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=5)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=json.dumps(data), timeout=5)
            
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            if response.content:
                return response.json()
            return {} # Return an empty dict for success with no content
        
        except requests.exceptions.HTTPError as err:
            if err.response.content:
                try:
                    error_data = err.response.json()
                    print(f"API Error: {error_data.get('message', 'Unknown error')}")
                except json.JSONDecodeError:
                    print(f"API Error (Non-JSON): HTTP {err.response.status_code}: {err.response.text}")
            else:
                 print(f"API Error: HTTP Error: {err}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"API Error: Could not connect to server at {self.base_url}")
            return None
        except requests.exceptions.Timeout:
            print(f"API Error: Request timed out connecting to {self.base_url}")
            return None
        except Exception as e:
            print(f"API Error: An unexpected error occurred: {e}")
            return None

    def register(self, username, password):
        return self._request('POST', '/register', {'username': username, 'password': password})

    def login(self, username, password):
        return self._request('POST', '/login', {'username': username, 'password': password})

    def upload_key(self, public_key_pem):
        return self._request('POST', '/upload_key', {'public_key': public_key_pem})

    def get_key(self, username):
        return self._request('GET', '/get_key', params={'username': username})

    def request_chat(self, recipient_username):
        return self._request('POST', '/request_chat', {'recipient_username': recipient_username})

    def get_chat_requests(self):
        return self._request('GET', '/get_chat_requests')

    def accept_chat(self, requester_username):
        return self._request('POST', '/accept_chat', {'requester_username': requester_username})

    def send_message(self, recipient_username, encrypted_blob):
        return self._request('POST', '/send_message', {'recipient_username': recipient_username, 'encrypted_blob': encrypted_blob})

    def get_messages(self, username):
        return self._request('GET', '/get_messages', params={'username': username})
    
    def get_contacts(self):
        return self._request('GET', '/get_contacts')

# --- CryptoHelper: Handles all encryption/decryption (Unchanged) ---
class CryptoHelper:
    def __init__(self):
        self.private_key = None

    def generate_keys(self):
        """Generates a new RSA private/public key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return self.private_key

    def save_private_key(self, private_key, password, filename):
        """Saves the private key to a file, encrypted with the user's password."""
        if not password:
            raise ValueError("A password is required to save the private key.")
            
        with open(filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
            ))

    def load_private_key(self, password, filename):
        """Loads the private key from a file, decrypting it with the password."""
        if not password:
            raise ValueError("A password is required to load the private key.")
            
        try:
            with open(filename, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode('utf-8'),
                )
            return self.private_key
        except FileNotFoundError:
            return None
        except (TypeError, ValueError):
            # Raised for bad password/corrupt key
            return None

    def export_public_key_pem(self, private_key=None):
        """Returns the public key in PEM format."""
        key = private_key or self.private_key
        if not key:
            raise ValueError("No private key loaded or provided.")
        
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def load_public_key_pem(self, pem_data):
        """Loads a public key from PEM string data."""
        return serialization.load_pem_public_key(pem_data.encode('utf-8'))

    def encrypt(self, plain_text, public_key):
        """Encrypts a message (as bytes) using a public key."""
        encrypted = public_key.encrypt(
            plain_text, # Assumes plain_text is already bytes
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_blob):
        """Decrypts a message using the loaded private key."""
        if not self.private_key:
            raise ValueError("Private key not loaded.")
        
        try:
            encrypted_data = base64.b64decode(encrypted_blob)
            plain_text_bytes = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plain_text_bytes.decode('utf-8')
            
        except (base64.binascii.Error, ValueError):
            return "[Error: Could not decode message. (Bad base64)]"
        except cryptography.exceptions.InvalidKey:
            return "[Error: Could not decrypt. Key mismatch?]"
        except Exception as e:
            return f"[Error: Decryption failed. ({type(e).__name__})]"


# --- Qt Polling Worker (Thread-safe) ---
class PollingWorker(QObject):
    """
    Runs in a separate thread to poll the server without freezing the UI.
    """
    messages_received = Signal(dict)
    requests_received = Signal(dict)
    connection_error = Signal(str)

    def __init__(self, api):
        super().__init__()
        self.api = api
        self._current_partner = None
        self._is_running = True

    @Slot(str)
    def set_chat_partner(self, partner_username):
        """Slot to update the partner from the main thread."""
        self._current_partner = partner_username

    @Slot()
    def stop(self):
        """Slot to stop the polling loop."""
        self._is_running = False

    @Slot()
    def run(self):
        """The main polling loop."""
        while self._is_running:
            partner = self._current_partner # Thread-safe copy
            
            # 1. Poll for messages for the active partner
            if partner:
                messages_data = self.api.get_messages(partner)
                if messages_data is not None:
                    # Only emit if the partner hasn't changed
                    if partner == self._current_partner:
                        self.messages_received.emit(messages_data)
                else:
                    self.connection_error.emit(f"Could not fetch messages for {partner}.")
            
            # 2. Poll for new chat requests
            requests_data = self.api.get_chat_requests()
            if requests_data is not None:
                self.requests_received.emit(requests_data)
            else:
                self.connection_error.emit("Could not fetch chat requests.")

            # Interruptible sleep
            for _ in range(30): # 30 * 100ms = 3 seconds
                if not self._is_running:
                    break
                QThread.msleep(100)
        print("Polling thread stopped.")

# --- Qt Login/Register Widget ---
class LoginWidget(QWidget):
    """
    The first screen the user sees. Handles login, registration,
    and homeserver configuration.
    """
    # Signal: (api_client, crypto_helper, username, password)
    login_success = Signal(APIClient, CryptoHelper, str, str)

    def __init__(self):
        super().__init__()
        self.config = self._load_config()
        
        self.api = APIClient(self.config['homeserver'])
        self.crypto = CryptoHelper()

        self._init_ui()

    def _init_ui(self):
        # Outer layout centers a card
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(18, 18, 18, 18)
        root_layout.setSpacing(0)
        root_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Card container (gives the 'webui card' look)
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 18, 18, 18)
        card_layout.setSpacing(12)

        # Title
        title = QLabel("Secure E2EE Chat")
        title.setObjectName("heading")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)

        # Status (smaller, centered)
        self.status_label = QLabel("")
        self.status_label.setObjectName("status")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(self.status_label)

        # Homeserver
        hs_label = QLabel("Homeserver URL:")
        hs_label.setObjectName("subheading")
        card_layout.addWidget(hs_label)
        self.homeserver_edit = QLineEdit(self.config['homeserver'])
        self.homeserver_edit.setPlaceholderText("e.g., http://127.0.0.1:5000")
        card_layout.addWidget(self.homeserver_edit)

        # Username
        un_label = QLabel("Username:")
        card_layout.addWidget(un_label)
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter your username")
        card_layout.addWidget(self.username_edit)

        # Password
        pw_label = QLabel("Password:")
        card_layout.addWidget(pw_label)
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter your password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        card_layout.addWidget(self.password_edit)

        # Buttons (aligned right-ish)
        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        button_row.addStretch(1)
        self.register_button = QPushButton("Register")
        self.register_button.setObjectName("secondary")
        self.login_button = QPushButton("Login")
        self.login_button.setMinimumWidth(100)
        button_row.addWidget(self.register_button)
        button_row.addWidget(self.login_button)
        card_layout.addLayout(button_row)

        # Constrain card size for readability on small windows
        card.setMaximumWidth(520)
        card.setMinimumWidth(360)

        # Add card to root layout
        root_layout.addWidget(card)
        self.setLayout(root_layout)

        # connections (keep your existing ones)
        self.login_button.clicked.connect(self._on_login)
        self.register_button.clicked.connect(self._on_register)
        self.username_edit.returnPressed.connect(self._on_login)
        self.password_edit.returnPressed.connect(self._on_login)


    def _load_config(self):
        """Loads config from file, or creates it."""
        if not os.path.exists(CONFIG_FILE):
            config = {'homeserver': DEFAULT_HOMESERVER}
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
            return config
        else:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)

    def _save_config(self, homeserver_url):
        """Saves config to file."""
        self.config['homeserver'] = homeserver_url
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f)

    def _set_loading(self, is_loading):
        """Disables UI elements during a request."""
        self.status_label.setText("Connecting..." if is_loading else "")
        self.login_button.setEnabled(not is_loading)
        self.register_button.setEnabled(not is_loading)
        self.username_edit.setEnabled(not is_loading)
        self.password_edit.setEnabled(not is_loading)
        self.homeserver_edit.setEnabled(not is_loading)
        QApplication.processEvents()

    @Slot()
    def _on_login(self):
        username = self.username_edit.text()
        password = self.password_edit.text()
        homeserver = self.homeserver_edit.text()
        
        if not username or not password or not homeserver:
            self.status_label.setText("All fields are required.")
            return

        self._set_loading(True)
        
        # Update API client and save config
        self.api.set_base_url(homeserver)
        self._save_config(homeserver)

        response = self.api.login(username, password)
        if response and 'token' in response:
            self.api.token = response['token']
            
            # Try to load the private key
            key_file = f"{username}_private.pem"
            if not self.crypto.load_private_key(password, key_file):
                self.status_label.setText("Login OK, but failed to load private key. Wrong password or missing key file?")
                self._set_loading(False)
                return
            
            # SUCCESS
            self.login_success.emit(self.api, self.crypto, username, password)
        else:
            self.status_label.setText("Login Failed. Check credentials or server.")
            self._set_loading(False)

    @Slot()
    def _on_register(self):
        username = self.username_edit.text()
        password = self.password_edit.text()
        homeserver = self.homeserver_edit.text()

        if not username or not password or not homeserver:
            self.status_label.setText("All fields are required.")
            return

        self._set_loading(True)
        
        # Update API client and save config
        self.api.set_base_url(homeserver)
        self._save_config(homeserver)
        
        key_file = f"{username}_private.pem"
        if os.path.exists(key_file):
            if not self._show_confirm("Warning", f"A key file for '{username}' already exists. Registering will overwrite it. Continue?"):
                self._set_loading(False)
                return

        # 1. Register
        if self.api.register(username, password) is None:
            self.status_label.setText("Registration failed. Username may be taken.")
            self._set_loading(False)
            return
            
        # 2. Login to get token
        response = self.api.login(username, password)
        if not response or 'token' not in response:
            self.status_label.setText("Registered, but failed to log in.")
            self._set_loading(False)
            return
            
        self.api.token = response['token']
        
        # 3. Generate, save, and upload keys
        try:
            priv_key = self.crypto.generate_keys()
            self.crypto.save_private_key(priv_key, password, key_file)
            pub_key_pem = self.crypto.export_public_key_pem()

            if self.api.upload_key(pub_key_pem) is None:
                self.status_label.setText("Account created, but key upload failed.")
                self._set_loading(False)
                return
        except Exception as e:
            self.status_label.setText(f"Key generation error: {e}")
            self._set_loading(False)
            return

        # SUCCESS
        self._show_info("Success", "Registered, keys generated, and public key uploaded! Welcome.")
        self.login_success.emit(self.api, self.crypto, username, password)
    
    def _show_info(self, title, text):
        QMessageBox.information(self, title, text)
        
    def _show_confirm(self, title, text):
        reply = QMessageBox.question(self, title, text, 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)
        return reply == QMessageBox.StandardButton.Yes


# --- Qt Main Chat Widget ---
class MainChatWidget(QWidget):
    """
    The main two-pane chat interface.
    """
    # Signal to tell the worker to change partners
    partner_changed = Signal(str)

    def __init__(self, api, crypto, username):
        super().__init__()
        self.api = api
        self.crypto = crypto
        self.username = username
        
        self.current_partner = None
        self.key_cache = {} # Caches partner public keys
        self.chat_cache = {} # Caches message IDs to prevent duplicates
        
        self._init_ui()
        self._init_polling()
        
    def _init_ui(self):
        layout = QHBoxLayout(self)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setHandleWidth(4)
        self.splitter.setChildrenCollapsible(False)

        # --- Left Pane ---
        left_pane = QWidget()
        left_layout = QVBoxLayout(left_pane)
        left_layout.setContentsMargins(6, 6, 6, 6)
        left_layout.setSpacing(8)

        self.new_chat_button = QPushButton("Start New Chat")
        left_layout.addWidget(self.new_chat_button)

        req_label = QLabel("Chat Requests")
        req_label.setObjectName("subheading")
        left_layout.addWidget(req_label)

        self.requests_list = QListWidget()
        self.requests_list.setMinimumHeight(100)
        left_layout.addWidget(self.requests_list)

        contacts_label = QLabel("Contacts")
        contacts_label.setObjectName("subheading")
        left_layout.addWidget(contacts_label)

        self.contacts_list = QListWidget()
        left_layout.addWidget(self.contacts_list)
        self._load_contacts()

        # --- Right Pane ---
        right_pane = QWidget()
        right_layout = QVBoxLayout(right_pane)
        right_layout.setContentsMargins(6, 6, 6, 6)
        right_layout.setSpacing(8)

        self.chat_partner_label = QLabel("Select a contact to chat")
        self.chat_partner_label.setObjectName("subheading")
        self.chat_partner_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.addWidget(self.chat_partner_label)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        right_layout.addWidget(self.chat_display, stretch=1)

        # Send Box
        send_layout = QHBoxLayout()
        self.message_entry = QLineEdit()
        self.message_entry.setPlaceholderText("Type your encrypted message...")
        self.send_button = QPushButton("Send")
        self.send_button.setMinimumWidth(100)

        send_layout.addWidget(self.message_entry, stretch=1)
        send_layout.addWidget(self.send_button)
        right_layout.addLayout(send_layout)

        # --- Add panes to splitter ---
        self.splitter.addWidget(left_pane)
        self.splitter.addWidget(right_pane)
        self.splitter.setStretchFactor(0, 0)  # Left pane stays fixed
        self.splitter.setStretchFactor(1, 1)  # Right pane expands
        self.splitter.setSizes([260, 700])    # Initial proportional sizing

        layout.addWidget(self.splitter)
        self.setLayout(layout)

        # --- Connections ---
        self.new_chat_button.clicked.connect(self._on_new_chat)
        self.requests_list.itemClicked.connect(self._on_request_selected)
        self.contacts_list.itemClicked.connect(self._on_contact_selected)
        self.send_button.clicked.connect(self._on_send_message)
        self.message_entry.returnPressed.connect(self._on_send_message)

        # Disable chat until partner is selected
        self.message_entry.setEnabled(False)
        self.send_button.setEnabled(False)


    def _init_polling(self):
        """Set up the background polling thread and worker."""
        self.polling_thread = QThread(self)
        self.polling_worker = PollingWorker(self.api)
        
        self.polling_worker.moveToThread(self.polling_thread)
        
        # Connect signals and slots
        self.polling_thread.started.connect(self.polling_worker.run)
        self.polling_worker.messages_received.connect(self._on_messages_received)
        self.polling_worker.requests_received.connect(self._on_requests_received)
        self.polling_worker.connection_error.connect(self._on_connection_error)
        
        # Connect our partner_changed signal to the worker's slot
        self.partner_changed.connect(self.polling_worker.set_chat_partner)
        
        self.polling_thread.start()
        print("Polling thread started.")

    def shutdown(self):
        """Cleanly shuts down the polling thread."""
        print("Shutting down polling thread...")
        self.polling_worker.stop()
        self.polling_thread.quit()
        if not self.polling_thread.wait(3000): # Wait 3s
            print("Polling thread did not exit cleanly. Terminating.")
            self.polling_thread.terminate()

    @Slot()
    def _on_new_chat(self):
        username, ok = QInputDialog.getText(self, "Start New Chat", "Enter username to chat with:")
        if ok and username:
            if username == self.username:
                self._show_error("Wait", "You can't chat with yourself!")
                return
            
            if self.api.request_chat(username) is not None:
                self._show_info("Request Sent", f"Chat request sent to {username}.")
                # Add to contacts immediately
                self._add_to_list(self.contacts_list, username)
            else:
                self._show_error("Error", f"Could not send chat request to {username}. User may not exist.")

    @Slot(QListWidgetItem)
    def _on_request_selected(self, item):
        username = item.text()
        if self._show_confirm("Accept Chat", f"Accept chat request from {username}?"):
            if self.api.accept_chat(username) is not None:
                # Remove from requests list
                self.requests_list.takeItem(self.requests_list.row(item))
                # Add to contacts list
                self._add_to_list(self.contacts_list, username)
                # Auto-select
                self._select_chat_partner(username)
            else:
                self._show_error("Error", "Could not accept chat request.")

    @Slot(QListWidgetItem)
    def _on_contact_selected(self, item):
        username = item.text()
        self._select_chat_partner(username)

    def _load_contacts(self):
        """Fetches and populates the contact list from the server."""
        response = self.api.get_contacts()
        if response and 'contacts' in response:
            self.contacts_list.clear()
            for username in response['contacts']:
                self._add_to_list(self.contacts_list, username)
        else:
            print("Could not load contacts.")

    def _select_chat_partner(self, username):
        """Switches the main chat view to a new partner."""
        if self.current_partner == username:
            return
            
        self.current_partner = username
        self.chat_partner_label.setText(f"Chatting with: {username}")
        self._add_message_to_display(f"Loading chat history with {username}...", 'system')
        
        # Enable chat
        self.message_entry.setEnabled(True)
        self.send_button.setEnabled(True)
        self.message_entry.setFocus()

        # Tell the polling worker to switch partners
        self.partner_changed.emit(username)
        
        # Load history
        self._load_chat_history(username)

    def _load_chat_history(self, username):
        """Fetches and displays the full chat history."""
        # Ensure we have the partner's public key
        if username not in self.key_cache:
            key_data = self.api.get_key(username)
            if not key_data or 'public_key' not in key_data:
                self._add_message_to_display(f"Error: Could not get public key for {username}.", 'system')
                self.current_partner = None
                self.chat_partner_label.setText("Select a contact to chat")
                self.message_entry.setEnabled(False)
                self.send_button.setEnabled(False)
                return
            try:
                self.key_cache[username] = self.crypto.load_public_key_pem(key_data['public_key'])
            except Exception as e:
                self._add_message_to_display(f"Error: Could not parse public key for {username}. {e}", 'system')
                return

        # Fetch messages
        history = self.api.get_messages(username)
        
        self.chat_display.clear()
        
        if history and 'messages' in history:
            self.chat_cache[username] = set() # Reset cache
            for msg in history['messages']:
                self._process_message(msg, is_history=True)
            self._add_message_to_display(f"--- End of history ---", 'system')
        elif history is not None:
            self._add_message_to_display(f"No messages yet. Say hello!", 'system')
        else:
            self._add_message_to_display(f"Could not load messages.", 'system')
            
    @Slot()
    def _on_send_message(self):
        text = self.message_entry.text()
        if not text or not self.current_partner:
            return
            
        partner_key = self.key_cache.get(self.current_partner)
        if not partner_key:
            self._show_error("Error", "Don't have this user's public key. Cannot send.")
            return

        try:
            text_bytes = text.encode('utf-8')
            if len(text_bytes) > RSA_MAX_MESSAGE_BYTES:
                self._show_error("Message Too Long", 
                    f"Your message is too long ({len(text_bytes)} bytes). "
                    f"The limit for this RSA chat is {RSA_MAX_MESSAGE_BYTES} bytes.")
                return

            encrypted_blob = self.crypto.encrypt(text_bytes, partner_key)
            
            if self.api.send_message(self.current_partner, encrypted_blob) is not None:
                # Add to UI immediately
                self._add_message_to_display(f"{self.username} (You): {text}", 'self')
                self.message_entry.clear()
            else:
                self._add_message_to_display(f"Failed to send message.", 'system')
        
        except Exception as e:
            self._show_error("Encryption Error", f"Could not encrypt message: {e}")

    @Slot(dict)
    def _on_messages_received(self, data):
        """Processes a new batch of messages from the polling thread."""
        if data.get('messages'):
            for msg in data['messages']:
                self._process_message(msg)

    @Slot(dict)
    def _on_requests_received(self, data):
        """Updates the chat requests Listbox."""
        if 'pending_requests' not in data:
            return
            
        current_requests = set(self.requests_list.item(i).text() for i in range(self.requests_list.count()))
        new_requests = set(req['requester_username'] for req in data['pending_requests'])
        
        # Add new ones
        for user in new_requests - current_requests:
            self.requests_list.addItem(user)
        
        # Remove old ones
        for user in current_requests - new_requests:
            items = self.requests_list.findItems(user, Qt.MatchFlag.MatchExactly)
            if items:
                self.requests_list.takeItem(self.requests_list.row(items[0]))

    @Slot(str)
    def _on_connection_error(self, error_message):
        """Shows a connection error. (Could be rate-limited later)"""
        print(error_message) # Avoid spamming the user
        # You could add a status bar icon here
        
    def _process_message(self, msg, is_history=False):
        """Decrypts and displays a single message if it's new."""
        partner = self.current_partner
        if not partner: return

        if partner not in self.chat_cache:
            self.chat_cache[partner] = set()

        msg_id = msg['id']
        if msg_id not in self.chat_cache[partner]:
            self.chat_cache[partner].add(msg_id)
            
            if msg['sender_username'] == self.username:
                if is_history:
                    self._add_message_to_display(f"{self.username} (You): {self.crypto.decrypt(msg['encrypted_blob'])}", 'self')
                # If not history, we already added it in _on_send_message. Do nothing.
            else:
                # Message from our partner
                decrypted_text = self.crypto.decrypt(msg['encrypted_blob'])
                self._add_message_to_display(f"{msg['sender_username']}: {decrypted_text}", 'other')

    def _add_message_to_display(self, message, tag):
        """Adds a styled message to the QTextEdit using HTML."""
        if tag == 'self':
            # Blue
            html = f"<p style='color: #89b4fa; text-align: right; margin: 2px 0;'>{message}</p>"
        elif tag == 'other':
            # Default text
            html = f"<p style='color: #cdd6f4; text-align: left; margin: 2px 0;'>{message}</p>"
        else: # 'system'
            # Gray, italic
            html = f"<p style='color: #7f849c; text-align: center; margin: 2px 0;'><i>{message}</i></p>"
            
        self.chat_display.append(html)
        self.chat_display.verticalScrollBar().setValue(
            self.chat_display.verticalScrollBar().maximum()
        )

    def _add_to_list(self, list_widget, username):
        """Adds a username to a QListWidget if not already present."""
        if not list_widget.findItems(username, Qt.MatchFlag.MatchExactly):
            list_widget.addItem(username)

    def _show_info(self, title, text):
        QMessageBox.information(self, title, text)
        
    def _show_error(self, title, text):
        QMessageBox.critical(self, title, text)
        
    def _show_confirm(self, title, text):
        reply = QMessageBox.question(self, title, text, 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)
        return reply == QMessageBox.StandardButton.Yes


# --- Qt Main Window (Shell) ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat Client")
        self.setGeometry(100, 100, 900, 700)
        
        self.main_chat_widget = None
        
        self.login_widget = LoginWidget()
        self.login_widget.login_success.connect(self._on_login_success)
        
        self.setCentralWidget(self.login_widget)
        
    @Slot(APIClient, CryptoHelper, str, str)
    def _on_login_success(self, api, crypto, username, password):
        """Swaps the central widget from Login to the Main Chat."""
        self.main_chat_widget = MainChatWidget(api, crypto, username)
        self.setCentralWidget(self.main_chat_widget)
        self.setWindowTitle(f"Secure Chat Client - Logged in as {username}")

    def closeEvent(self, event):
        """Handles the window close event to shut down threads."""
        if self.main_chat_widget:
            self.main_chat_widget.shutdown()
        event.accept()


# --- Main Execution ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(GLOBAL_STYLESHEET)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())