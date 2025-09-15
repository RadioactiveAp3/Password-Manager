#!/usr/bin/env python3
"""
Password Manager - A secure, local password manager with AES-256 encryption
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bcrypt
import pyotp
import qrcode
from PIL import Image, ImageTk
import io

class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Database and encryption
        self.db_path = "passwords.db"
        self.config_path = "config.json"
        self.master_password = None
        self.fernet = None
        
        # Initialize database
        self.init_database()
        
        # Check if first time setup
        if self.is_first_time():
            self.show_setup()
        else:
            self.show_login()
    
    def init_database(self):
        """Initialize SQLite database with proper schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                website TEXT,
                notes TEXT,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create categories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                color TEXT DEFAULT '#6c757d',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert default category if none exists
        cursor.execute('SELECT COUNT(*) FROM categories')
        if cursor.fetchone()[0] == 0:
            cursor.execute('INSERT INTO categories (name, color) VALUES (?, ?)', 
                         ('General', '#6c757d'))
        
        conn.commit()
        conn.close()
    
    def is_first_time(self):
        """Check if this is the first time running the app"""
        return not os.path.exists(self.config_path)
    
    def show_setup(self):
        """Show first-time setup dialog"""
        self.clear_window()
        
        # Setup frame
        setup_frame = tk.Frame(self.root, bg='#f0f0f0')
        setup_frame.pack(expand=True, fill='both')
        
        # Center the setup dialog
        setup_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Title
        title_label = tk.Label(setup_frame, text="🔐 Password Manager Setup", 
                              font=('Arial', 24, 'bold'), bg='#f0f0f0')
        title_label.pack(pady=20)
        
        # Subtitle
        subtitle_label = tk.Label(setup_frame, text="Create your master password to get started", 
                                 font=('Arial', 12), bg='#f0f0f0', fg='#666')
        subtitle_label.pack(pady=10)
        
        # Password frame
        password_frame = tk.Frame(setup_frame, bg='#f0f0f0')
        password_frame.pack(pady=20)
        
        # Master password
        tk.Label(password_frame, text="Master Password:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w')
        self.master_pw_entry = tk.Entry(password_frame, show='*', font=('Arial', 12), width=30)
        self.master_pw_entry.pack(pady=5, ipady=8)
        
        # Confirm password
        tk.Label(password_frame, text="Confirm Password:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(10,0))
        self.confirm_pw_entry = tk.Entry(password_frame, show='*', font=('Arial', 12), width=30)
        self.confirm_pw_entry.pack(pady=5, ipady=8)
        
        # Password strength indicator
        self.strength_label = tk.Label(password_frame, text="", font=('Arial', 10), bg='#f0f0f0')
        self.strength_label.pack(pady=5)
        
        # Bind password strength check
        self.master_pw_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Setup button
        setup_btn = tk.Button(password_frame, text="Create Master Password", 
                             command=self.setup_master_password,
                             font=('Arial', 12, 'bold'), bg='#007bff', fg='white',
                             width=20, height=2, relief='flat')
        setup_btn.pack(pady=20)
        
        # Focus on password entry
        self.master_pw_entry.focus()
    
    def check_password_strength(self, event):
        """Check and display password strength"""
        password = self.master_pw_entry.get()
        strength = self.calculate_password_strength(password)
        
        if strength < 3:
            self.strength_label.config(text="Weak password", fg='red')
        elif strength < 5:
            self.strength_label.config(text="Medium password", fg='orange')
        else:
            self.strength_label.config(text="Strong password", fg='green')
    
    def calculate_password_strength(self, password):
        """Calculate password strength score"""
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        return score
    
    def setup_master_password(self):
        """Setup master password"""
        password = self.master_pw_entry.get()
        confirm = self.confirm_pw_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return
        
        # Hash the master password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Save config
        from datetime import datetime
        config = {
            'master_password_hash': hashed_password.decode('utf-8'),
            'created_at': str(datetime.now())
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(config, f)
        
        messagebox.showinfo("Success", "Master password created successfully!")
        self.master_password = password
        self.setup_encryption()
        self.show_main_interface()
    
    def show_login(self):
        """Show login dialog"""
        self.clear_window()
        
        # Login frame
        login_frame = tk.Frame(self.root, bg='#f0f0f0')
        login_frame.pack(expand=True, fill='both')
        
        # Center the login dialog
        login_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Title
        title_label = tk.Label(login_frame, text="🔐 Password Manager", 
                              font=('Arial', 24, 'bold'), bg='#f0f0f0')
        title_label.pack(pady=20)
        
        # Subtitle
        subtitle_label = tk.Label(login_frame, text="Enter your master password", 
                                 font=('Arial', 12), bg='#f0f0f0', fg='#666')
        subtitle_label.pack(pady=10)
        
        # Password frame
        password_frame = tk.Frame(login_frame, bg='#f0f0f0')
        password_frame.pack(pady=20)
        
        # Master password
        tk.Label(password_frame, text="Master Password:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w')
        self.master_pw_entry = tk.Entry(password_frame, show='*', font=('Arial', 12), width=30)
        self.master_pw_entry.pack(pady=5, ipady=8)
        
        # Login button
        login_btn = tk.Button(password_frame, text="Login", 
                             command=self.login,
                             font=('Arial', 12, 'bold'), bg='#007bff', fg='white',
                             width=20, height=2, relief='flat')
        login_btn.pack(pady=20)
        
        # Focus on password entry
        self.master_pw_entry.focus()
        
        # Bind Enter key to login
        self.master_pw_entry.bind('<Return>', lambda e: self.login())
    
    def login(self):
        """Handle login"""
        password = self.master_pw_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return
        
        # Load config
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            messagebox.showerror("Error", "No master password found. Please run setup first.")
            return
        
        # Verify password
        stored_hash = config['master_password_hash'].encode('utf-8')
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            messagebox.showerror("Error", "Invalid master password")
            return
        
        self.master_password = password
        self.setup_encryption()
        self.show_main_interface()
    
    def setup_encryption(self):
        """Setup encryption using master password"""
        # Derive key from master password
        password = self.master_password.encode()
        salt = b'password_manager_salt'  # In production, use a random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.fernet = Fernet(key)
    
    def show_main_interface(self):
        """Show main password manager interface"""
        self.clear_window()
        
        # Create main frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_frame, bg='#f0f0f0')
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Title
        title_label = tk.Label(header_frame, text="🔐 Password Manager", 
                              font=('Arial', 20, 'bold'), bg='#f0f0f0')
        title_label.pack(side='left')
        
        # Add password button
        add_btn = tk.Button(header_frame, text="+ Add Password", 
                           command=self.show_add_password_dialog,
                           font=('Arial', 12, 'bold'), bg='#28a745', fg='white',
                           relief='flat', padx=20, pady=10)
        add_btn.pack(side='right')
        
        # Search frame
        search_frame = tk.Frame(main_frame, bg='#f0f0f0')
        search_frame.pack(fill='x', pady=(0, 20))
        
        # Search entry
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_passwords)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, 
                               font=('Arial', 12), width=50)
        search_entry.pack(side='left', padx=(0, 10))
        search_entry.insert(0, "Search passwords...")
        search_entry.bind('<FocusIn>', self.clear_search_placeholder)
        search_entry.bind('<FocusOut>', self.restore_search_placeholder)
        
        # Refresh button
        refresh_btn = tk.Button(search_frame, text="🔄 Refresh", 
                               command=self.load_passwords,
                               font=('Arial', 10), bg='#6c757d', fg='white',
                               relief='flat')
        refresh_btn.pack(side='left')
        
        # Passwords list frame
        list_frame = tk.Frame(main_frame, bg='white', relief='sunken', bd=1)
        list_frame.pack(fill='both', expand=True)
        
        # Create Treeview for passwords
        columns = ('Title', 'Username', 'Website', 'Category', 'Created')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.tree.heading('Title', text='Title')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Website', text='Website')
        self.tree.heading('Category', text='Category')
        self.tree.heading('Created', text='Created')
        
        self.tree.column('Title', width=200)
        self.tree.column('Username', width=150)
        self.tree.column('Website', width=200)
        self.tree.column('Category', width=100)
        self.tree.column('Created', width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Bind double-click event
        self.tree.bind('<Double-1>', self.show_password_details)
        
        # Load passwords
        self.load_passwords()
    
    def clear_search_placeholder(self, event):
        """Clear search placeholder text"""
        if self.search_var.get() == "Search passwords...":
            self.search_var.set("")
    
    def restore_search_placeholder(self, event):
        """Restore search placeholder text"""
        if not self.search_var.get():
            self.search_var.set("Search passwords...")
    
    def filter_passwords(self, *args):
        """Filter passwords based on search term"""
        # Check if tree exists (main interface might not be loaded yet)
        if not hasattr(self, 'tree'):
            return
            
        search_term = self.search_var.get().lower()
        if search_term == "search passwords...":
            search_term = ""
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load and filter passwords
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if search_term:
            cursor.execute('''
                SELECT id, title, username, website, category, created_at
                FROM passwords
                WHERE title LIKE ? OR username LIKE ? OR website LIKE ? OR category LIKE ?
                ORDER BY title
            ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        else:
            cursor.execute('''
                SELECT id, title, username, website, category, created_at
                FROM passwords
                ORDER BY title
            ''')
        
        for row in cursor.fetchall():
            self.tree.insert('', 'end', values=(
                row[1],  # title
                row[2],  # username
                row[3] or '',  # website
                row[4],  # category
                row[5][:10] if row[5] else ''  # created_at (date only)
            ), tags=(str(row[0]),))  # Store ID in tags
        
        conn.close()
    
    def load_passwords(self):
        """Load all passwords into the treeview"""
        self.filter_passwords()
    
    def show_add_password_dialog(self):
        """Show add password dialog"""
        dialog = AddPasswordDialog(self.root, self)
    
    def show_password_details(self, event):
        """Show password details dialog"""
        item = self.tree.selection()[0]
        password_id = self.tree.item(item, 'tags')[0]
        
        # Get password details
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM passwords WHERE id = ?', (password_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            dialog = PasswordDetailsDialog(self.root, self, row)
    
    def add_password(self, title, username, password, website, notes, category):
        """Add a new password"""
        # Encrypt password
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (title, username, encrypted_password, website, notes, category)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (title, username, encrypted_password, website, notes, category))
        conn.commit()
        conn.close()
        
        # Refresh the list
        self.load_passwords()
    
    def get_password(self, password_id):
        """Get decrypted password"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_password FROM passwords WHERE id = ?', (password_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            encrypted_password = row[0]
            return self.fernet.decrypt(encrypted_password.encode()).decode()
        return None
    
    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()

class AddPasswordDialog:
    def __init__(self, parent, password_manager):
        self.parent = parent
        self.password_manager = password_manager
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Add New Password")
        self.dialog.geometry("500x700")
        self.dialog.configure(bg='#f0f0f0')
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create dialog widgets"""
        # Title
        title_label = tk.Label(self.dialog, text="Add New Password", 
                              font=('Arial', 18, 'bold'), bg='#f0f0f0')
        title_label.pack(pady=20)
        
        # Form frame
        form_frame = tk.Frame(self.dialog, bg='#f0f0f0')
        form_frame.pack(fill='both', expand=True, padx=40, pady=20)
        
        # Title field
        tk.Label(form_frame, text="Title:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 5))
        self.title_entry = tk.Entry(form_frame, font=('Arial', 12), width=40)
        self.title_entry.pack(pady=(0, 15), ipady=5)
        
        # Username field
        tk.Label(form_frame, text="Username/Email:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 5))
        self.username_entry = tk.Entry(form_frame, font=('Arial', 12), width=40)
        self.username_entry.pack(pady=(0, 15), ipady=5)
        
        # Password field
        tk.Label(form_frame, text="Password:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 5))
        password_frame = tk.Frame(form_frame, bg='#f0f0f0')
        password_frame.pack(fill='x', pady=(0, 15))
        
        self.password_entry = tk.Entry(password_frame, show='*', font=('Arial', 12), width=30)
        self.password_entry.pack(side='left', ipady=5)
        
        # Generate password button
        generate_btn = tk.Button(password_frame, text="Generate", 
                                command=self.generate_password,
                                font=('Arial', 10), bg='#17a2b8', fg='white',
                                relief='flat')
        generate_btn.pack(side='left', padx=(10, 0))
        
        # Show/hide password button
        self.show_password_var = tk.BooleanVar()
        show_btn = tk.Checkbutton(password_frame, text="Show", 
                                 variable=self.show_password_var,
                                 command=self.toggle_password_visibility,
                                 font=('Arial', 10), bg='#f0f0f0')
        show_btn.pack(side='left', padx=(10, 0))
        
        # Website field
        tk.Label(form_frame, text="Website:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 5))
        self.website_entry = tk.Entry(form_frame, font=('Arial', 12), width=40)
        self.website_entry.pack(pady=(0, 15), ipady=5)
        
        # Category field
        tk.Label(form_frame, text="Category:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 5))
        self.category_entry = tk.Entry(form_frame, font=('Arial', 12), width=40)
        self.category_entry.insert(0, "General")
        self.category_entry.pack(pady=(0, 15), ipady=5)
        
        # Notes field
        tk.Label(form_frame, text="Notes:", font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 5))
        self.notes_text = tk.Text(form_frame, font=('Arial', 12), width=40, height=4)
        self.notes_text.pack(pady=(0, 20), ipady=5)
        
        # Buttons - positioned at bottom
        button_frame = tk.Frame(self.dialog, bg='#f0f0f0')
        button_frame.pack(side='bottom', fill='x', padx=40, pady=20)
        
        cancel_btn = tk.Button(button_frame, text="Cancel", 
                              command=self.dialog.destroy,
                              font=('Arial', 12), bg='#6c757d', fg='white',
                              relief='flat', padx=20, pady=10)
        cancel_btn.pack(side='right', padx=(10, 0))
        
        save_btn = tk.Button(button_frame, text="Save Password", 
                            command=self.save_password,
                            font=('Arial', 12, 'bold'), bg='#007bff', fg='white',
                            relief='flat', padx=20, pady=10)
        save_btn.pack(side='right')
        
        # Focus on title entry
        self.title_entry.focus()
    
    def generate_password(self):
        """Generate a random password"""
        import random
        import string
        
        length = 16
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')
    
    def save_password(self):
        """Save the new password"""
        title = self.title_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        website = self.website_entry.get().strip()
        notes = self.notes_text.get('1.0', tk.END).strip()
        category = self.category_entry.get().strip() or "General"
        
        if not title or not username or not password:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
        
        try:
            self.password_manager.add_password(title, username, password, website, notes, category)
            messagebox.showinfo("Success", "Password saved successfully!")
            self.dialog.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")

class PasswordDetailsDialog:
    def __init__(self, parent, password_manager, password_data):
        self.parent = parent
        self.password_manager = password_manager
        self.password_data = password_data
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Password Details")
        self.dialog.geometry("500x500")
        self.dialog.configure(bg='#f0f0f0')
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create dialog widgets"""
        # Title
        title_label = tk.Label(self.dialog, text="Password Details", 
                              font=('Arial', 18, 'bold'), bg='#f0f0f0')
        title_label.pack(pady=20)
        
        # Details frame
        details_frame = tk.Frame(self.dialog, bg='#f0f0f0')
        details_frame.pack(fill='both', expand=True, padx=40, pady=20)
        
        # Title
        tk.Label(details_frame, text="Title:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(anchor='w')
        tk.Label(details_frame, text=self.password_data[1], font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 15))
        
        # Username
        tk.Label(details_frame, text="Username:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(anchor='w')
        tk.Label(details_frame, text=self.password_data[2], font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 15))
        
        # Password
        tk.Label(details_frame, text="Password:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(anchor='w')
        password_frame = tk.Frame(details_frame, bg='#f0f0f0')
        password_frame.pack(fill='x', pady=(0, 15))
        
        self.password_label = tk.Label(password_frame, text="••••••••", font=('Arial', 12), bg='#f0f0f0')
        self.password_label.pack(side='left')
        
        show_btn = tk.Button(password_frame, text="Show", 
                            command=self.toggle_password_display,
                            font=('Arial', 10), bg='#17a2b8', fg='white',
                            relief='flat')
        show_btn.pack(side='left', padx=(10, 0))
        
        copy_btn = tk.Button(password_frame, text="Copy", 
                            command=self.copy_password,
                            font=('Arial', 10), bg='#28a745', fg='white',
                            relief='flat')
        copy_btn.pack(side='left', padx=(5, 0))
        
        # Website
        if self.password_data[3]:
            tk.Label(details_frame, text="Website:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(anchor='w')
            tk.Label(details_frame, text=self.password_data[3], font=('Arial', 12), bg='#f0f0f0', fg='blue', cursor='hand2').pack(anchor='w', pady=(0, 15))
        
        # Category
        tk.Label(details_frame, text="Category:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(anchor='w')
        tk.Label(details_frame, text=self.password_data[4], font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 15))
        
        # Notes
        if self.password_data[5]:
            tk.Label(details_frame, text="Notes:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(anchor='w')
            notes_text = tk.Text(details_frame, font=('Arial', 12), width=40, height=3, wrap='word')
            notes_text.pack(fill='x', pady=(0, 15))
            notes_text.insert('1.0', self.password_data[5])
            notes_text.config(state='disabled')
        
        # Created date
        tk.Label(details_frame, text="Created:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(anchor='w')
        tk.Label(details_frame, text=self.password_data[6], font=('Arial', 12), bg='#f0f0f0').pack(anchor='w', pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(details_frame, bg='#f0f0f0')
        button_frame.pack(fill='x')
        
        close_btn = tk.Button(button_frame, text="Close", 
                             command=self.dialog.destroy,
                             font=('Arial', 12), bg='#6c757d', fg='white',
                             relief='flat', padx=20, pady=10)
        close_btn.pack(side='right')
        
        self.password_shown = False
    
    def toggle_password_display(self):
        """Toggle password display"""
        if not self.password_shown:
            # Decrypt and show password
            decrypted_password = self.password_manager.get_password(self.password_data[0])
            if decrypted_password:
                self.password_label.config(text=decrypted_password)
                self.password_shown = True
        else:
            # Hide password
            self.password_label.config(text="••••••••")
            self.password_shown = False
    
    def copy_password(self):
        """Copy password to clipboard"""
        decrypted_password = self.password_manager.get_password(self.password_data[0])
        if decrypted_password:
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(decrypted_password)
            messagebox.showinfo("Success", "Password copied to clipboard!")

if __name__ == "__main__":
    app = PasswordManager()
    app.root.mainloop()
