# 🔐 Password Manager

A secure, local password manager with AES-256 encryption built in Python with a modern GUI.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES--256-red.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

## ✨ Features

- **🔒 AES-256 Encryption**: All passwords are encrypted using industry-standard AES-256 encryption
- **🛡️ Master Password Protection**: Secure master password with bcrypt hashing
- **📱 Modern GUI**: Clean, intuitive interface built with tkinter
- **🔍 Search & Filter**: Quickly find passwords with real-time search
- **📂 Categories**: Organize passwords by categories
- **🎲 Password Generator**: Built-in secure password generator
- **📋 Copy to Clipboard**: One-click password copying
- **💾 Local Storage**: All data stored locally in SQLite database
- **🔐 Show/Hide Passwords**: Toggle password visibility
- **📝 Notes**: Add notes to your password entries

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Windows, macOS, or Linux

### Installation

1. **Clone or download this repository**
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```
   
   Or on Windows, double-click `run_password_manager.bat`

### First Time Setup

1. **Create Master Password**: When you first run the app, you'll be prompted to create a master password
2. **Password Requirements**: 
   - At least 8 characters long
   - Mix of letters, numbers, and symbols recommended
3. **Remember Your Password**: This is the only password you need to remember!

## 📖 How to Use

### Adding Passwords
1. Click the **"+ Add Password"** button
2. Fill in the required fields:
   - **Title**: Name for the password (e.g., "Gmail Account")
   - **Username/Email**: Your login username
   - **Password**: Your password (or use the generator)
   - **Website**: Optional website URL
   - **Category**: Organize by category (default: "General")
   - **Notes**: Optional additional information
3. Click **"Save Password"**

### Viewing Passwords
1. **Double-click** any password in the list to view details
2. Click **"Show"** to reveal the password
3. Click **"Copy"** to copy the password to clipboard

### Searching Passwords
- Use the search box to filter passwords by title, username, website, or category
- Search is real-time and case-insensitive

### Password Generator
- Click **"Generate"** in the add password dialog
- Generates a secure 16-character password with mixed characters

## 🔧 Technical Details

### Security Features
- **AES-256 Encryption**: Industry-standard encryption for all passwords
- **PBKDF2 Key Derivation**: 100,000 iterations for key derivation
- **bcrypt Hashing**: Secure master password hashing
- **Local Storage**: All data stays on your device

### Database Schema
- **SQLite Database**: Lightweight, file-based database
- **Encrypted Storage**: All sensitive data is encrypted
- **Categories**: Flexible categorization system

### Dependencies
- `cryptography`: AES-256 encryption
- `bcrypt`: Password hashing
- `pyotp`: 2FA support (future feature)
- `qrcode`: QR code generation (future feature)
- `pillow`: Image processing

## 🛠️ Development

### Project Structure
```
password_manager/
├── main.py                 # Main application
├── requirements.txt        # Python dependencies
├── run_password_manager.bat # Windows launcher
├── README.md              # This file
├── passwords.db           # SQLite database (created on first run)
└── config.json           # Configuration file (created on first run)
```

### Building Executable (Optional)
To create a standalone executable:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed main.py
```

## 🔒 Security Considerations

- **Master Password**: Choose a strong, unique master password
- **Local Storage**: Your data is stored locally and encrypted
- **No Cloud Sync**: This is intentionally a local-only solution
- **Regular Backups**: Consider backing up your `passwords.db` file

## 🐛 Troubleshooting

### Common Issues

1. **"No module named 'cryptography'"**
   - Run: `pip install -r requirements.txt`

2. **"Database is locked"**
   - Close any other instances of the app
   - Restart the application

3. **"Invalid master password"**
   - Make sure you're using the correct master password
   - Check for typos or caps lock

### Reset Application
To reset the application (⚠️ **WARNING**: This will delete all passwords):
1. Delete `passwords.db`
2. Delete `config.json`
3. Restart the application

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## ⚠️ Disclaimer

This software is provided "as is" without warranty. Always keep backups of your important data and use strong, unique passwords.