# Cortex Password Manager

A hardware-backed password manager implemented in Rust, featuring military-grade encryption and hardware-bound key derivation for maximum security.

## Overview

Cortex is a command-line password manager that uses ChaCha20-Poly1305 authenticated encryption combined with hardware fingerprinting to create unique encryption keys. The system binds passwords to specific hardware configurations, making unauthorized access significantly more difficult even if the database is compromised.

## Features

- **Hardware-Bound Encryption**: Keys are derived using hardware characteristics (CPU brand, system components)
- **ChaCha20-Poly1305 AEAD**: Military-grade authenticated encryption
- **BLAKE3 Hashing**: High-performance cryptographic hashing for key derivation
- **Secure Memory Handling**: Automatic memory zeroing using the `zeroize` crate
- **Embedded Database**: Uses Sled for efficient, embedded storage
- **Password Generation**: Built-in secure password generator with customizable options
- **Search Functionality**: Search entries by name or description with regex support
- **Export Capability**: Export all passwords to plain text with security verification
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
- Separate nonce for description encryption
- Timestamp for audit purposes

## Installation

Clones the Cortex repository from GitHub to your local machine

```bash
git clone https://github.com/naseridev/cortex.git
```

Changes the current directory to the cloned cortex folder

```bash
cd cortex
```

Builds and installs the Cortex project using Cargo (Rust's package manager)

```bash
cargo install --path .
```

Verifies the installation by displaying the Cortex version

```bash
cortex --version
```

Alternatively, you can download pre-compiled versions from the Releases section.

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
# Master password: [hidden input - min 8 chars with complexity requirements]
# Confirm password: [hidden input]
# Output: "Initialized."
```

### Creating Password Entries
Store a new password with optional description:
```bash
cortex create "github-work"
# Prompts:
# Master password: [hidden input]
# Password to store: [hidden input - min 4 chars]
# Confirm password: [hidden input]
# Description (optional): Work GitHub account for project X
# Output: "Created 'github-work'."
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
# Entry: aws-prod
# Description: Production AWS credentials
#
# Entry: github-work
# Description: Work GitHub account for project X
```

### Modifying Existing Entries
Change password and description for existing entries:
```bash
cortex edit "github-work"
# Prompts:
# Master password: [hidden input]
# New password (Enter to keep current): [hidden input - min 4 chars]
# Confirm new password: [hidden input]
# New description (Enter to keep current): Updated GitHub credentials
# Output: "Edited for 'github-work'."
```

### Removing Entries
Delete a password entry permanently:
```bash
cortex delete "old-account"
# Prompts:
# Master password: [hidden input]
# Output: "Deleted 'old-account'." or "Not found: old-account"
```

### Searching Entries
Find entries by name or description:
```bash
cortex find "github"
# Basic search

cortex find "aws" --ignore-case --names-only
# Case-insensitive search in names only

# Prompts:
# Master password: [hidden input]
# Output: Shows matching entries with match indicators
```

### Password Generation
Generate secure passwords:
```bash
cortex pass
# Generates one 16-character password with default settings

cortex pass --length 20 --count 3 --no-ambiguous
# Generates 3 passwords, 20 characters each, excluding ambiguous characters

cortex pass --length 12 --uppercase false --special false
# Generates password with only lowercase letters and digits
```

**Generator Options:**
- `--length, -e`: Password length (default: 16, max: 128)
- `--count, -c`: Number of passwords to generate (default: 1, max: 50)
- `--uppercase, -u`: Include uppercase letters (default: true)
- `--lowercase, -l`: Include lowercase letters (default: true)
- `--digits, -d`: Include digits (default: true)
- `--special, -s`: Include special characters (default: true)
- `--no-ambiguous, -n`: Exclude ambiguous characters (0, O, l, 1, etc.)

### Export Database
Export all passwords to a plain text file:
```bash
cortex export
# Prompts:
# Master password: [hidden input]
# WARNING: This will export all passwords in plain text format.
# Solve this equation to confirm: (47 + 23) * 3
# Answer: [hidden input - must solve math puzzle]
# Output: Export completed to cortex_export_[timestamp].dat
```

### Master Password Management
Change the master password (re-encrypts all data):
```bash
cortex reset
# Prompts:
# Current master password: [hidden input]
# New master password: [hidden input - min 8 chars with complexity requirements]
# Confirm new password: [hidden input]
# Output: "Master password reset."
```

### Database Destruction
Permanently destroy the entire password database:
```bash
cortex purge
# Security verification:
# WARNING: This will permanently delete all stored passwords!
# Solve this equation to confirm: (47 + 23) * 3
# Answer: [hidden input - must solve math puzzle]
# Master password: [hidden input]
# Output: "Database purged."
```

## Common Error Scenarios

```bash
# Database already exists
cortex init
# Output: "Database exists. Use 'reset' command."

# Duplicate entry
cortex create "existing-account"
# Output: "Error: Account 'existing-account' already exists. Use 'edit' to update or choose a different name."

# Weak master password
cortex init
# Master password: weak123
# Output: "Error: Password must contain at least 3 of these 4 types: lowercase, uppercase, digit, special character. Missing: uppercase, special character"

# Description security violation
cortex create "secure-app"
# Password to store: mySecretPass123
# Description: My password is mySecretPass123
# Output: "Error: Description cannot contain the password or parts of it."

# Empty search pattern
cortex find ""
# Output: "Error: Search pattern cannot be empty."
```

## Configuration

The database is automatically created in the system's configuration directory:
- **Linux**: `~/.config/cortex/.password-store`
- **macOS**: `~/Library/Application Support/cortex/.password-store`
- **Windows**: `%APPDATA%/cortex/.password-store`

## Security Considerations

- **Hardware Binding**: Database cannot be transferred between different systems
- **Memory Security**: All sensitive data is automatically zeroed after use
- **Master Password Complexity**: Enforced requirements for strong master passwords
- **Account Password Strength**: Minimum 4-character requirement for stored passwords
- **Information Leakage Prevention**: Descriptions cannot contain password fragments
- **Export Security**: Mathematical puzzle verification required for sensitive operations
- **Search Limitations**: Pattern length limits and result count restrictions to prevent abuse

## Password Security Requirements

### Master Password
- Minimum 8 characters
- Must contain at least 3 of the following 4 types:
  - Lowercase letters
  - Uppercase letters
  - Digits
  - Special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)

### Account Passwords
- Minimum 4 characters
- No maximum length limit
- Cannot appear in the description field

## Dependencies

- `blake3`: High-performance cryptographic hashing
- `chacha20poly1305`: Authenticated encryption
- `sled`: Embedded database engine
- `clap`: Command-line argument parsing
- `sysinfo`: Hardware information gathering
- `zeroize`: Secure memory clearing
- `rpassword`: Secure password input
- `rand`: Cryptographically secure random number generation
- `regex`: Pattern matching for search functionality
- `serde`: Serialization/deserialization
- `bincode`: Binary serialization format
- `dirs`: Standard directory locations

## Technical Specifications

- **Encryption**: ChaCha20-Poly1305 with 256-bit keys
- **Nonce Size**: 96-bit (12 bytes) for both password and description
- **Hash Function**: BLAKE3 with hardware salt
- **Database**: Sled embedded key-value store
- **Memory Management**: Automatic secure clearing via Drop trait
- **Input Limits**: 128 characters for passwords, 72 for descriptions and inputs
- **Search Limits**: 100 characters for patterns, 10,000 entries maximum processing

## Command Reference

| Command | Purpose | Arguments |
|---------|---------|-----------|
| `init` | Initialize new database | None |
| `create <name>` | Create new password entry | Entry name |
| `get <name>` | Retrieve password entry | Entry name |
| `list` | List all entries | None |
| `delete <name>` | Delete password entry | Entry name |
| `edit <name>` | Edit existing entry | Entry name |
| `find <pattern>` | Search entries | Pattern, optional flags |
| `pass` | Generate passwords | Optional generation parameters |
| `export` | Export all passwords | None |
| `reset` | Change master password | None |
| `purge` | Destroy entire database | None |

---

***Critical Warning**:* *This software binds encryption keys to hardware characteristics. Transferring the database to different hardware will result in permanent data loss. Always use the export function before hardware changes.*
