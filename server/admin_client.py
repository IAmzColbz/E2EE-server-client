import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, filedialog
import sqlite3
import os

class AdminApplication(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Chat Server Admin")
        self.geometry("900x600")
        
        self.db_path = None
        
        # --- Main Frame ---
        main_frame = tk.Frame(self)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # --- DB Path Entry ---
        db_frame = tk.Frame(main_frame)
        db_frame.pack(fill='x', pady=5)
        
        self.db_label = tk.Label(db_frame, text="Database File:", width=15, anchor='w')
        self.db_label.pack(side=tk.LEFT)
        
        self.db_path_var = tk.StringVar(value="Click 'Browse' to load chat_server.db")
        self.db_entry = tk.Entry(db_frame, textvariable=self.db_path_var, state='disabled')
        self.db_entry.pack(side=tk.LEFT, fill='x', expand=True, padx=5)
        
        self.browse_button = tk.Button(db_frame, text="Browse...", command=self._browse_for_db)
        self.browse_button.pack(side=tk.LEFT)
        
        # --- Notebook (Tabs) ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True, pady=10)
        
        # We will create tabs, but only *after* the DB is loaded
        self.tab_users = None
        self.tab_keys = None
        self.tab_messages = None
        self.tab_requests = None
        
        self.tree_users = None
        
        # --- Bottom Frame (Refresh) ---
        self.bottom_frame = tk.Frame(main_frame)
        self.bottom_frame.pack(fill='x')
        
        self.refresh_button = tk.Button(self.bottom_frame, text="Refresh All Data", command=self._refresh_all_tables, state='disabled')
        self.refresh_button.pack(side=tk.RIGHT)
        
        self.status_var = tk.StringVar(value="Please load a database file.")
        self.status_bar = tk.Label(self.bottom_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w')
        self.status_bar.pack(side=tk.LEFT, fill='x', expand=True, ipady=2)
        
    def _browse_for_db(self):
        """Asks user to find the chat_server.db file."""
        path = filedialog.askopenfilename(
            title="Select chat_server.db",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        if path and os.path.exists(path):
            self.db_path = path
            self.db_path_var.set(path)
            self.status_var.set(f"Loaded: {path}")
            self.refresh_button.config(state='normal')
            
            # Create tabs if they don't exist
            if not self.tab_users:
                self._create_tabs()
                
            self._refresh_all_tables()
        elif path:
            messagebox.showerror("Error", "File not found. Please check the path.")

    def _create_tabs(self):
        """Creates the notebook tabs for viewing data."""
        # --- Users Tab ---
        self.tab_users = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_users, text='Users')
        self.tree_users = self._create_treeview(
            self.tab_users, 
            columns=('id', 'username', 'password_hash'),
            headings=('User ID', 'Username', 'Password Hash')
        )
        self.delete_user_button = tk.Button(self.tab_users, text="Delete Selected User", command=self._delete_selected_user, bg="#ffaaaa")
        self.delete_user_button.pack(side=tk.BOTTOM, fill='x', pady=5)
        
        # --- Public Keys Tab ---
        self.tab_keys = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_keys, text='Public Keys')
        self.tree_keys = self._create_treeview(
            self.tab_keys,
            columns=('user_id', 'public_key'),
            headings=('User ID', 'Public Key')
        )
        
        # --- Messages Tab ---
        self.tab_messages = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_messages, text='Messages')
        self.tree_messages = self._create_treeview(
            self.tab_messages,
            columns=('id', 'sender_id', 'recipient_id', 'timestamp', 'encrypted_blob'),
            headings=('Msg ID', 'Sender ID', 'Recipient ID', 'Timestamp', 'Encrypted Data')
        )
        
        # --- Chat Requests Tab ---
        self.tab_requests = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_requests, text='Chat Requests')
        self.tree_requests = self._create_treeview(
            self.tab_requests,
            columns=('id', 'requester_id', 'requested_id', 'status'),
            headings=('Req ID', 'Requester ID', 'Requested ID', 'Status')
        )

    def _create_treeview(self, parent_frame, columns, headings):
        """Helper to create a scrollable treeview (table)."""
        scroll_y = tk.Scrollbar(parent_frame, orient=tk.VERTICAL)
        scroll_x = tk.Scrollbar(parent_frame, orient=tk.HORIZONTAL)
        
        tree = ttk.Treeview(
            parent_frame, 
            columns=columns, 
            show='headings', 
            yscrollcommand=scroll_y.set, 
            xscrollcommand=scroll_x.set
        )
        
        scroll_y.config(command=tree.yview)
        scroll_x.config(command=tree.xview)
        
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(side=tk.LEFT, fill='both', expand=True)
        
        for i, col in enumerate(columns):
            tree.heading(col, text=headings[i])
            tree.column(col, width=150, anchor='w')
            
        return tree

    def _get_db_conn(self):
        """Connects to the database path."""
        if not self.db_path:
            self.status_var.set("Error: Database path is not set.")
            return None, None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn, conn.cursor()
        except sqlite3.Error as e:
            self.status_var.set(f"DB Error: {e}")
            messagebox.showerror("Database Error", f"Could not connect to database: {e}")
            return None, None

    def _refresh_all_tables(self):
        """Fetches fresh data for all tables."""
        if not self.db_path:
            messagebox.showerror("Error", "Please select a database file first.")
            return
            
        self.status_var.set("Refreshing data...")
        self._populate_tree(self.tree_users, "SELECT id, username, password_hash FROM users ORDER BY id")
        self._populate_tree(self.tree_keys, "SELECT user_id, public_key FROM public_keys ORDER BY user_id")
        self._populate_tree(self.tree_messages, "SELECT id, sender_id, recipient_id, timestamp, encrypted_blob FROM messages ORDER BY timestamp DESC")
        self._populate_tree(self.tree_requests, "SELECT id, requester_id, requested_id, status FROM chat_requests ORDER BY id")
        self.status_var.set("Data refreshed.")

    def _populate_tree(self, tree, query):
        """Generic helper to clear and fill a treeview from a query."""
        if not tree:
            return
            
        # Clear existing data
        for row in tree.get_children():
            tree.delete(row)
            
        conn, cursor = self._get_db_conn()
        if not conn:
            return
            
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                tree.insert("", tk.END, values=list(row))
        except sqlite3.Error as e:
            self.status_var.set(f"Query Error: {e}")
            messagebox.showerror("Query Error", f"Failed to execute query for {tree}:\n{e}")
        finally:
            conn.close()

    def _delete_selected_user(self):
        """Deletes a user and all their associated data."""
        try:
            selected_item = self.tree_users.focus()
            if not selected_item:
                messagebox.showwarning("No Selection", "Please select a user from the table to delete.")
                return
                
            item_data = self.tree_users.item(selected_item)
            user_id = item_data['values'][0]
            username = item_data['values'][1]
            
            if not messagebox.askyesno("Confirm Delete", 
                f"Are you sure you want to permanently delete user:\n\n"
                f"ID: {user_id}\n"
                f"Username: {username}\n\n"
                f"This will also delete ALL their messages (sent and received), "
                f"public keys, and chat requests. This action cannot be undone."
            ):
                return

            # Proceed with deletion
            conn, cursor = self._get_db_conn()
            if not conn:
                return

            try:
                self.status_var.set(f"Deleting user {username} (ID: {user_id})...")
                
                # --- Manual Cascade Delete ---
                # 1. Delete public key
                cursor.execute("DELETE FROM public_keys WHERE user_id = ?", (user_id,))
                
                # 2. Delete messages (sent and received)
                cursor.execute("DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?", (user_id, user_id))
                
                # 3. Delete chat requests (sent and received)
                cursor.execute("DELETE FROM chat_requests WHERE requester_id = ? OR requested_id = ?", (user_id, user_id))
                
                # 4. Delete the user
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                
                conn.commit()
                self.status_var.set(f"Successfully deleted user {username}.")
                messagebox.showinfo("Success", f"User {username} and all their data has been deleted.")
                
            except sqlite3.Error as e:
                conn.rollback()
                self.status_var.set(f"Error during deletion: {e}")
                messagebox.showerror("Deletion Error", f"An error occurred: {e}")
            finally:
                conn.close()
                
            # Refresh tables to show the change
            self._refresh_all_tables()

        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            self.status_var.set(f"Error: {e}")

if __name__ == "__main__":
    app = AdminApplication()
    app.mainloop()
