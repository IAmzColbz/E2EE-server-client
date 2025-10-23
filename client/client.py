import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import requests
import json
import os
import threading
import time
from queue import Queue
import base64

# --- Cryptography Imports ---
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions

# --- Configuration ---
CONFIG_FILE = 'client_config.json'
PRIVATE_KEY_FILE = 'client_private.pem'
DEFAULT_HOMESERVER = 'http://127.0.0.1:5000'
# Max bytes for an RSA-2048-OAEP-SHA256 encrypted message
# (2048 bits / 8) - (2 * 256 bits / 8) - 2 = 256 - 64 - 2 = 190 bytes
RSA_MAX_MESSAGE_BYTES = 190

# --- APIClient: Handles all server communication ---
class APIClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token

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
                response = requests.get(url, headers=headers, params=params)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=json.dumps(data))
            
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            if response.content:
                return response.json()
            return {} # Return an empty dict for success with no content
        
        except requests.exceptions.HTTPError as err:
            if err.response.content:
                try:
                    error_data = err.response.json()
                    messagebox.showerror("API Error", f"Error: {error_data.get('message', 'Unknown error')}")
                except json.JSONDecodeError:
                    messagebox.showerror("API Error", f"HTTP {err.response.status_code}: {err.response.text}")
            else:
                 messagebox.showerror("API Error", f"HTTP Error: {err}")
            return None
        except requests.exceptions.ConnectionError:
            messagebox.showerror("Connection Error", f"Could not connect to server at {self.base_url}")
            return None
        except Exception as e:
            messagebox.showerror("Request Error", f"An unexpected error occurred: {e}")
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

# --- CryptoHelper: Handles all encryption/decryption ---
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

    def save_private_key(self, private_key, password, filename=PRIVATE_KEY_FILE):
        """Saves the private key to a file, encrypted with the user's password."""
        if not password:
            raise ValueError("A password is required to save the private key.")
            
        with open(filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                # Encrypt the key using the provided password
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
            ))

    def load_private_key(self, password, filename=PRIVATE_KEY_FILE):
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
        except TypeError:
            # This is often raised if the password is wrong
            return None
        except ValueError:
            # Also raised for bad password/corrupt key
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
        # We must base64 encode the binary data to send it as JSON
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_blob):
        """Decrypts a message using the loaded private key."""
        if not self.private_key:
            raise ValueError("Private key not loaded.")
        
        try:
            # 1. Decode from base64
            encrypted_data = base64.b64decode(encrypted_blob)
            
            # 2. Decrypt with private key
            plain_text_bytes = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # 3. Decode from UTF-8
            return plain_text_bytes.decode('utf-8')
            
        except (base64.binascii.Error, ValueError):
            return "[Error: Could not decode message. (Bad base64)]"
        except cryptography.exceptions.InvalidKey:
            return "[Error: Could not decrypt. Key mismatch?]"
        except Exception as e:
            # Broad catch for other crypto errors (e.g., padding)
            return f"[Error: Decryption failed. ({type(e).__name__})]"

# --- Main Chat Application (Tkinter GUI) ---
class ChatApplication(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Chat Client")
        self.geometry("800x600")

        self.api = None
        self.crypto = CryptoHelper()
        self.token = None
        self.username = None
        
        self.current_partner = None
        self.key_cache = {} # Caches public keys of partners
        self.chat_cache = {} # Caches message IDs to avoid re-rendering
        
        self.polling_thread = None
        self.stop_polling_event = threading.Event() # For clean shutdown
        self.update_queue = Queue()

        self._load_config()
        self.api = APIClient(self.config['homeserver'])
        self._show_auth_frame()
        
        # Set up a clean shutdown
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _load_config(self):
        """Loads config from file, or creates it."""
        if not os.path.exists(CONFIG_FILE):
            self.config = {'homeserver': DEFAULT_HOMESERVER}
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f)
        else:
            with open(CONFIG_FILE, 'r') as f:
                self.config = json.load(f)

    def _show_auth_frame(self):
        """Displays the Login/Register UI."""
        self.auth_frame = tk.Frame(self, padx=10, pady=10)
        self.auth_frame.pack(expand=True)

        tk.Label(self.auth_frame, text="Username").pack()
        self.username_entry = tk.Entry(self.auth_frame, width=30)
        self.username_entry.pack()

        tk.Label(self.auth_frame, text="Password").pack()
        self.password_entry = tk.Entry(self.auth_frame, show="*", width=30)
        self.password_entry.pack(pady=5)

        tk.Button(self.auth_frame, text="Login", command=self._login).pack(fill='x', pady=5)
        tk.Button(self.auth_frame, text="Register", command=self._handle_register).pack(fill='x')

    def _login(self):
        """Handles the login button click."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required.")
            return

        response = self.api.login(username, password)
        if response and 'token' in response:
            self.token = response['token']
            self.username = username
            self.api.token = self.token
            
            # --- EDIT: Define user-specific key file ---
            private_key_file = f"{username}_private.pem"
            
            # Try to load the private key USING THE PASSWORD
            try:
                # --- EDIT: Pass the specific filename ---
                if not self.crypto.load_private_key(password=password, filename=private_key_file):
                    # File not found or password was wrong
                    messagebox.showerror("Login Error", "Login successful, but private key not found or password was incorrect.\n"
                                         "Ensure you are on the same machine you registered with.")
                    self.token = None
                    self.username = None
                    self.api.token = None
                    return
            except (ValueError, TypeError) as e:
                messagebox.showerror("Key Error", f"Failed to load private key. Is it corrupted? Error: {e}")
                return
            
            self._show_main_frame()
        else:
            # APIClient already showed an error, but as a fallback:
            if response is None:
                pass # Error already shown
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")

    def _handle_register(self):
        """Handles the register button click."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required.")
            return

        # --- EDIT: Define user-specific key file ---
        private_key_file = f"{username}_private.pem"

        # Check if key file already exists
        # --- EDIT: Check for the user's specific file ---
        if os.path.exists(private_key_file):
            if not messagebox.askyesno("Warning", f"A private key file for '{username}' already exists. Registering will overwrite it. Continue?"):
                return

        if self.api.register(username, password) is not None:
            messagebox.showinfo("Success", "Registered! Now logging in and generating keys...")
            
            # After registering, log in to get a token
            response = self.api.login(username, password)
            if not response or 'token' not in response:
                messagebox.showerror("Error", "Registered, but failed to log in.")
                return

            self.token = response['token']
            self.username = username
            self.api.token = self.token
            
            try:
                # Generate and save keys
                priv_key = self.crypto.generate_keys()
                # SAVE THE KEY ENCRYPTED WITH THE PASSWORD
                # --- EDIT: Pass the specific filename ---
                self.crypto.save_private_key(priv_key, password=password, filename=private_key_file)
                pub_key_pem = self.crypto.export_public_key_pem()

                # Upload public key
                if self.api.upload_key(pub_key_pem) is not None:
                    messagebox.showinfo("Success", "Keys generated and public key uploaded! Welcome.")
                    self._show_main_frame()
                else:
                    messagebox.showerror("Error", "Registered and logged in, but failed to upload public key.")
            except Exception as e:
                messagebox.showerror("Key Generation Error", f"Failed to generate or save keys: {e}")
        else:
            pass # APIClient already showed error

    def _show_main_frame(self):
        """Displays the main chat UI after login."""
        self.auth_frame.destroy()
        self.main_frame = tk.Frame(self)
        self.main_frame.pack(fill='both', expand=True)

        # Main layout
        paned_window = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)

        # Left Pane (Contacts & Requests)
        left_pane = tk.Frame(paned_window, width=250)
        paned_window.add(left_pane, stretch="never")

        tk.Button(left_pane, text="Start New Chat", command=self._start_new_chat).pack(fill='x', pady=5)
        
        tk.Label(left_pane, text="Chat Requests", font=('Helvetica', 12, 'bold')).pack()
        self.requests_list = tk.Listbox(left_pane, height=5)
        self.requests_list.pack(fill='x', pady=5)
        self.requests_list.bind('<<ListboxSelect>>', self._on_select_request)
        
        tk.Label(left_pane, text="Contacts", font=('Helvetica', 12, 'bold')).pack()
        self.contacts_list = tk.Listbox(left_pane, height=15)
        self.contacts_list.pack(fill='both', expand=True)
        self.contacts_list.bind('<<ListboxSelect>>', self._on_select_contact)
        
        # Right Pane (Chat Window)
        right_pane = tk.Frame(paned_window, width=550)
        paned_window.add(right_pane)

        self.chat_partner_label = tk.Label(right_pane, text="Select a contact to chat", font=('Helvetica', 14, 'bold'))
        self.chat_partner_label.pack(pady=5)

        self.chat_display = scrolledtext.ScrolledText(right_pane, state='disabled', wrap=tk.WORD, height=20)
        self.chat_display.pack(fill='both', expand=True, padx=5, pady=5)
        # Configure tags for chat styling
        self.chat_display.tag_config('self', foreground='blue', justify='right')
        self.chat_display.tag_config('other', foreground='black', justify='left')
        self.chat_display.tag_config('system', foreground='gray', justify='center', font=('Helvetica', 9, 'italic'))

        # Message Entry
        entry_frame = tk.Frame(right_pane)
        entry_frame.pack(fill='x', padx=5, pady=5)
        self.message_entry = tk.Entry(entry_frame, width=60)
        self.message_entry.pack(side=tk.LEFT, fill='x', expand=True, ipady=5)
        self.send_button = tk.Button(entry_frame, text="Send", command=self._send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)
        self.message_entry.bind("<Return>", (lambda event: self._send_message()))

        # Start polling for updates
        self._start_polling()

    def _start_new_chat(self):
        """Prompts user to start a chat with a new user."""
        username = simpledialog.askstring("Start Chat", "Enter username to chat with:", parent=self)
        if username:
            if username == self.username:
                messagebox.showwarning("Wait", "You can't chat with yourself!")
                return
                
            if self.api.request_chat(username) is not None:
                messagebox.showinfo("Request Sent", f"Chat request sent to {username}.")
                # Add to contacts immediately for simplicity
                if username not in self.contacts_list.get(0, tk.END):
                    self.contacts_list.insert(tk.END, username)
            else:
                pass # APIClient already showed error

    def _on_select_request(self, event):
        """Handles clicking on a chat request."""
        try:
            selected_index = self.requests_list.curselection()[0]
            username = self.requests_list.get(selected_index)
            
            if messagebox.askyesno("Accept Chat", f"Accept chat request from {username}?"):
                if self.api.accept_chat(username) is not None:
                    self.requests_list.delete(selected_index)
                    if username not in self.contacts_list.get(0, tk.END):
                        self.contacts_list.insert(tk.END, username)
                    self._select_chat_partner(username)
        except IndexError:
            pass # Ignore empty selections

    def _on_select_contact(self, event):
        """Handles clicking on a contact."""
        try:
            selected_index = self.contacts_list.curselection()[0]
            username = self.contacts_list.get(selected_index)
            self._select_chat_partner(username)
        except IndexError:
            pass # Ignore empty selections

    def _select_chat_partner(self, username):
        """Switches the main chat view to a new partner."""
        if self.current_partner == username:
            return # Already selected
            
        self.current_partner = username
        self.chat_partner_label.config(text=f"Chatting with: {username}")
        
        # Clear chat display
        self._add_message_to_display(f"Loading chat history with {username}...", 'system')

        # Load history
        self._load_chat_history(username)

    def _load_chat_history(self, username):
        """Fetches and displays the full chat history."""
        # Ensure we have the partner's public key
        if username not in self.key_cache:
            key_data = self.api.get_key(username)
            if not key_data or 'public_key' not in key_data:
                self._add_message_to_display(f"Error: Could not get public key for {username}.", 'system')
                self.current_partner = None # Abort switch
                self.chat_partner_label.config(text="Select a contact to chat")
                return
            try:
                self.key_cache[username] = self.crypto.load_public_key_pem(key_data['public_key'])
            except Exception as e:
                self._add_message_to_display(f"Error: Could not parse public key for {username}. {e}", 'system')
                return

        # Fetch messages
        history = self.api.get_messages(username)
        
        self.chat_display.config(state='normal')
        self.chat_display.delete('1.0', tk.END) # Clear display
        self.chat_display.config(state='disabled')
            
        if history and 'messages' in history:
            self.chat_cache[username] = set() # Reset cache
            for msg in history['messages']:
                self._process_message(msg, is_history=True)
            self._add_message_to_display(f"--- End of history ---", 'system')
        elif history is not None:
            self._add_message_to_display(f"No messages yet. Say hello!", 'system')
        else:
            # get_messages failed, APIClient showed error
            self._add_message_to_display(f"Could not load messages.", 'system')

    def _send_message(self):
        """Encrypts and sends a message."""
        text = self.message_entry.get()
        if not text or not self.current_partner:
            return
        
        # Get partner's public key
        partner_key = self.key_cache.get(self.current_partner)
        if not partner_key:
            messagebox.showerror("Error", "Don't have this user's public key. Cannot send.")
            return

        try:
            # Check message size before encrypting
            text_bytes = text.encode('utf-8')
            if len(text_bytes) > RSA_MAX_MESSAGE_BYTES:
                messagebox.showerror("Message Too Long", 
                    f"Your message is too long ({len(text_bytes)} bytes). "
                    f"The limit for this simple RSA chat is {RSA_MAX_MESSAGE_BYTES} bytes.")
                return

            encrypted_blob = self.crypto.encrypt(text_bytes, partner_key)
            
            if self.api.send_message(self.current_partner, encrypted_blob) is not None:
                # Add to UI immediately
                self._add_message_to_display(f"{self.username} (You): {text}", 'self')
                self.message_entry.delete(0, tk.END)
                # Note: We no longer add a dummy_id to the cache.
                # The _process_message logic correctly handles duplicates.
            else:
                self._add_message_to_display(f"Failed to send message.", 'system')
        
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Could not encrypt message: {e}")

    def _add_message_to_display(self, message, tag):
        """Adds a message to the ScrolledText widget."""
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"{message}\n\n", tag)
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END) # Auto-scroll

    def _start_polling(self):
        """Starts the background polling thread."""
        self.stop_polling_event.clear()
        self.polling_thread = threading.Thread(
            target=self._poll_for_updates, 
            args=(self.stop_polling_event,), 
            daemon=True
        )
        self.polling_thread.start()
        # Start the queue checker
        self.after(100, self._process_update_queue)

    def _poll_for_updates(self, stop_event):
        """Background thread worker for polling."""
        while not stop_event.is_set():
            # Poll for new messages (if a chat is active)
            # Get partner *before* API call, in case it changes
            partner = self.current_partner
            if partner:
                messages_data = self.api.get_messages(partner)
                if messages_data:
                    # Tag the data with the partner it belongs to
                    self.update_queue.put(('messages', messages_data, partner))
            
            # Poll for new chat requests (always)
            requests_data = self.api.get_chat_requests()
            if requests_data:
                self.update_queue.put(('requests', requests_data))
            
            # Use event.wait for an interruptible sleep
            stop_event.wait(3) # Poll every 3 seconds

    def _process_update_queue(self):
        """Checks the queue for updates from the polling thread."""
        try:
            while not self.update_queue.empty():
                item = self.update_queue.get_nowait()
                msg_type = item[0]
                
                if msg_type == 'messages':
                    data, partner = item[1], item[2]
                    
                    # --- CRITICAL FIX ---
                    # Only process messages if they are for the *currently active* chat
                    if partner != self.current_partner:
                        continue # This is a stale update, ignore it
                        
                    if data.get('messages'):
                        for msg in data['messages']:
                            self._process_message(msg)
                            
                elif msg_type == 'requests':
                    data = item[1]
                    self._update_requests_list(data.get('pending_requests', []))
                    
        finally:
            # Reschedule itself, but only if we haven't been told to stop
            if not self.stop_polling_event.is_set():
                self.after(100, self._process_update_queue)

    def _process_message(self, msg, is_history=False):
        """Decrypts and displays a single message if it's new."""
        partner = self.current_partner
        if not partner: return # Should not happen, but a good guard

        if partner not in self.chat_cache:
            self.chat_cache[partner] = set()

        msg_id = msg['id']
        if msg_id not in self.chat_cache[partner]:
            # This is a new message
            self.chat_cache[partner].add(msg_id)
            
            if msg['sender_username'] == self.username:
                # This is one of our own messages, being loaded from history
                if is_history:
                    self._add_message_to_display(f"{self.username} (You): {self.crypto.decrypt(msg['encrypted_blob'])}", 'self')
                # If not history, it's a "live" message we sent.
                # We already added it to the UI in _send_message, so we do nothing.
            else:
                # This is a message from our partner
                decrypted_text = self.crypto.decrypt(msg['encrypted_blob'])
                self._add_message_to_display(f"{msg['sender_username']}: {decrypted_text}", 'other')

    def _update_requests_list(self, requests_list):
        """Updates the chat requests Listbox."""
        current_requests = set(self.requests_list.get(0, tk.END))
        new_requests = set(req['requester_username'] for req in requests_list)

        for user in new_requests - current_requests:
            self.requests_list.insert(tk.END, user)
        for user in current_requests - new_requests:
            try:
                idx = self.requests_list.get(0, tk.END).index(user)
                self.requests_list.delete(idx)
            except ValueError:
                pass # Item already gone

    def _on_closing(self):
        """Handle the window close event."""
        print("Closing application...")
        # Signal the polling thread to stop
        self.stop_polling_event.set()
        
        # Wait for the thread to finish
        if self.polling_thread and self.polling_thread.is_alive():
            print("Waiting for polling thread to exit...")
            self.polling_thread.join(timeout=1.0) # Wait up to 1 sec
            
        print("Exiting.")
        self.destroy()

# --- Main execution ---
if __name__ == "__main__":
    app = ChatApplication()
    app.mainloop()