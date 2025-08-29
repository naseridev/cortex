# Cortex Password Manager

A hardware-backed password manager implemented in Rust, featuring military-grade encryption and hardware-bound key derivation for maximum security.

## Overview

Cortex is a command-line password manager that uses ChaCha20-Poly1305 authenticated encryption combined with hardware fingerprinting to create unique encryption keys. The system binds passwords to specific hardware configurations, making unauthorized access significantly more difficult even if the database is compromised.

## Features

- **Hardware-Bound Encryption**: Keys are derived using hardware characteristics (CPU brand, system components)
- **ChaCha20-Poly1305 AEAD**: Military-grade authenticated encryption
- **BLAKE3 Hashing**: High-performance cryptographic hashing for key derivation
- **Secure Memory Handling**: Automatic memory zeroing using the `zeroize` crate
- **Lockout Protection**: Automatic lockout after failed authentication attempts
- **Embedded Database**: Uses Sled for efficient, embedded storage
- **Password Validation**: Built-in checks to prevent weak passwords and information leakage

## Security Architecture

### Key Derivation
```
Key = BLAKE3(master_password || hardware_fingerprint)
```

The hardware fingerprint is generated from:
- CPU brand information
- System component labels
- Hardware salt constant

### Data Structure
Each password entry contains:
- Encrypted password data
- Optional encrypted description
- Unique nonce for encryption
- Timestamp for audit purposes

## Installation


Clone and build from source:

```bash
git clone https://github.com/naseridev/cortex.git
```

```bash
cd cortex
```

```bash
cargo install --path .
```

```bash
cortex --version
```

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Rust Version**: 1.70.0 or later
- **RAM**: Minimum 100MB available memory
- **Storage**: 10MB for application + variable for password database
- **Hardware**: CPU with brand information accessible via system APIs

## Usage

### Database Initialization
Initialize a new password database with a master password:
```bash
cortex init
# Prompts:
# Master password: [hidden input - min 8 chars]
# Confirm password: [hidden input]
# Output: "Initialized."
```

### Adding Password Entries
Store a new password with optional description:
```bash
cortex add "github-work"
# Prompts:
# Master password: [hidden input]
# Password to store: [hidden input - min 4 chars]
# Confirm password: [hidden input]
# Description (optional): Work GitHub account for project X
# Output: "Added 'github-work'"
```

**Note**: Descriptions are limited to 72 characters and cannot contain the password or its fragments for security reasons.

### Retrieving Passwords
Access stored passwords:
```bash
cortex get "github-work"
# Prompts:
# Master password: [hidden input]
# Output:
# github-work: your_secure_password_123
# Description: Work GitHub account for project X
```

### Listing All Entries
View all stored password entries:
```bash
cortex list
# Prompts:
# Master password: [hidden input]
# Output:
#   aws-prod - Production AWS credentials
#   github-work - Work GitHub account for project X
#   ssh-server - Remote server access key
```

### Modifying Existing Entries
Change password and description for existing entries:
```bash
cortex change "github-work"
# Prompts:
# Master password: [hidden input]
# New password: [hidden input - min 4 chars]
# Confirm new password: [hidden input]
# New description (optional, max 72 chars): Updated GitHub credentials
# Output: "Changed password for 'github-work'"
```

### Removing Entries
Delete a password entry permanently:
```bash
cortex remove "old-account"
# Prompts:
# Master password: [hidden input]
# Output: "Removed 'old-account'" or "Not found: old-account"
```

### Master Password Management
Change the master password (re-encrypts all data):
```bash
cortex reset
# Prompts:
# Current master password: [hidden input]
# New master password: [hidden input - min 8 chars]
# Confirm new password: [hidden input]
# Output: "Master password reset."
```

### Database Destruction
Permanently destroy the entire password database:
```bash
cortex destroy
# Security verification:
# WARNING: This will permanently delete all stored passwords!
# Solve this equation to confirm: (47 + 23) * 3
# Answer: [hidden input - must solve math puzzle]
# Master password: [hidden input]
# Output: "Database destroyed."
```

**Common Error Scenarios:**
```bash
# Database already exists
cortex init
# Output: "Database exists. Use 'reset' command."

# Duplicate entry
cortex add "existing-account"
# Output: "Error: Account 'existing-account' already exists. Use 'change' to update or choose a different name."

# Weak password
cortex add "test"
# Password to store: 123
# Output: "Error: Password must be at least 4 characters"

# Description security violation
cortex add "secure-app"
# Password to store: mySecretPass123
# Description: My password is mySecretPass123
# Output: "Error: Description cannot contain the password or parts of it."
```

## Configuration

The database is automatically created in the system's configuration directory:
- **Linux**: `~/.config/cortex/passwords.db`
- **macOS**: `~/Library/Application Support/cortex/passwords.db`
- **Windows**: `%APPDATA%/cortex/passwords.db`

## Security Considerations

- **Hardware Binding**: Database cannot be transferred between different systems
- **Memory Security**: All sensitive data is automatically zeroed after use
- **Lockout Mechanism**: Multiple failed attempts trigger temporary lockout
- **Password Strength**: Enforced minimum lengths for master and account passwords
- **Information Leakage Prevention**: Descriptions cannot contain password fragments

## Dependencies

- `blake3`: High-performance cryptographic hashing
- `chacha20poly1305`: Authenticated encryption
- `sled`: Embedded database engine
- `clap`: Command-line argument parsing
- `sysinfo`: Hardware information gathering
- `zeroize`: Secure memory clearing
- `rpassword`: Secure password input

## Technical Specifications

- **Encryption**: ChaCha20-Poly1305 with 256-bit keys
- **Nonce Size**: 96-bit (12 bytes)
- **Hash Function**: BLAKE3
- **Database**: Sled embedded key-value store
- **Memory Management**: Automatic secure clearing via Drop trait

---

***Warning**: This software binds encryption keys to hardware characteristics. Transferring the database to different hardware will result in permanent data loss.*