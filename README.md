# Cortex Password Manager

A hardware-backed password manager implemented in Rust, featuring military-grade encryption, hardware-bound key derivation, and session management for maximum security.

## Overview

Cortex is a command-line password manager that uses ChaCha20-Poly1305 authenticated encryption combined with hardware fingerprinting to create unique encryption keys. The system binds passwords to specific hardware configurations, making unauthorized access significantly more difficult even if the database is compromised.

## Features

### Core Security
- **Hardware-Bound Encryption**: Keys are derived using hardware characteristics (CPU brand, system components)
- **ChaCha20-Poly1305 AEAD**: Military-grade authenticated encryption with authentication tags
- **BLAKE3 Hashing**: High-performance cryptographic hashing for key derivation (600,000 iterations)
- **Secure Memory Handling**: Automatic memory zeroing using the `zeroize` crate
- **Session Management**: Encrypted session caching with configurable timeouts and machine binding

### Password Management
- **Tag-Based Organization**: Organize passwords with multiple tags (up to 20 per entry)
- **Advanced Search**: Search by name, description, or tags with regex and case-insensitive options
- **Password Generation**: Secure password generator with customizable character sets
- **Clipboard Integration**: Copy passwords to clipboard with automatic clearing (3-540 seconds)
- **Description Support**: Optional descriptions (up to 500 characters) with security validation

### Data Management
- **JSON Import/Export**: Import and export passwords in structured JSON format
- **Template Generation**: Create sample import templates for bulk operations
- **Automatic Backups**: Backup creation before critical operations (keeps last 5 backups)
- **Batch Operations**: Add/remove tags and import multiple entries with validation
- **Rollback Support**: Automatic rollback on import failures

### User Experience
- **Session Caching**: Stay authenticated for configurable duration (default: 480 seconds / 8 minutes)
- **Configurable Settings**: Customize session timeout (60 seconds to 24 hours)
- **Lock Command**: Manually clear session when needed
- **Progress Indicators**: Real-time feedback for long-running operations
- **Validation**: Comprehensive input validation with helpful error messages

## Security Architecture

### Key Derivation
```
Hardware_ID = BLAKE3(CPU_Brand || "cortex_hardware_binding")
Derived_Key = BLAKE3^600000(Master_Password || Salt || Hardware_ID)
```

The hardware fingerprint is generated from:
- CPU brand information
- System component identifiers
- Hardware binding constant

### Session Security
```
Session_Key = BLAKE3^300000(CPU_Brand || "cortex_session_key_v3" || Session_Salt)
Encrypted_Session = ChaCha20Poly1305(Master_Password, Session_Key, Nonce)
```

Session validation includes:
- Machine hash verification (prevents cross-device session theft)
- Configurable timeout enforcement
- Maximum age limit (24 hours)
- Failed attempt tracking (max 3 attempts)
- Secure session file permissions (0600 on Unix)

### Data Structure
Each password entry contains:
- Encrypted password data (ChaCha20-Poly1305)
- Optional encrypted description (separate nonce)
- Optional encrypted tags (JSON serialized, separate nonce)
- Three unique 96-bit nonces (password, description, tags)
- Creation/modification timestamp

## Installation

### From Source

Clone the repository:
```bash
git clone https://github.com/naseridev/cortex.git
cd cortex
```

Build and install:
```bash
cargo install --path .
```

Verify installation:
```bash
cortex --version
# Output: cortex 3.0.0
```

### From Binary

Download pre-compiled binaries from the [Releases](https://github.com/naseridev/cortex/releases) page.

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Rust Version**: 1.70.0 or later (for building from source)
- **RAM**: Minimum 100MB available memory
- **Storage**: 10MB for application + variable for password database
- **Hardware**: CPU with brand information accessible via system APIs

## Usage

### Database Initialization
```bash
cortex init
```
**Prompts:**
- Master password: [hidden - min 8 chars with complexity requirements]
- Confirm password: [hidden]

**Output:** `Initialized.`

**Security Notes:**
- Master password requirements enforced
- Database and salt created in secure directory
- Initial backup created automatically
- File permissions set to 0700 (Unix)

### Creating Password Entries

**Basic creation:**
```bash
cortex create "github-work"
```

**With tags:**
```bash
cortex create "github-work" --tags "work,dev,critical"
```

**Prompts:**
- Master password: [hidden or cached session]
- Password to store: [hidden - min 4 chars]
- Confirm password: [hidden]
- Description (optional): [max 500 chars]

**Output:** `Created 'github-work'.` and `Tags: work, dev, critical`

**Validation:**
- Name cannot start with `__` (reserved prefix)
- Password minimum 4 characters
- Description cannot contain password fragments
- Description maximum 500 characters
- Tags normalized (lowercase, sorted, deduplicated)

### Retrieving Passwords

**Display in terminal:**
```bash
cortex get "github-work"
```

**Copy to clipboard (default 43s):**
```bash
cortex get "github-work" --clip
```

**Copy to clipboard (custom timeout):**
```bash
cortex get "github-work" --clip 120
```

**Output:**
```
github-work: your_secure_password_123
Description: Work GitHub account for project X
```

**Clipboard mode output:**
```
Password copied to clipboard for 120 seconds...
Description: Work GitHub account for project X
Done.
```

**Clipboard Options:**
- Timeout range: 3-540 seconds
- Default: 43 seconds
- Auto-clear after timeout
- Interrupt with Ctrl+C to clear immediately

### Listing Entries

**Basic list:**
```bash
cortex list
```

**With tags (deprecated flag, tags always shown):**
```bash
cortex list --tags
```

**Output:**
```
Entry: github-work
Description: Work GitHub account for project X
Tags: work, dev, critical

Entry: aws-prod
Description: Production AWS credentials
Tags: cloud, production
```

### Editing Entries

**Edit password and description:**
```bash
cortex edit "github-work"
```

**Replace tags:**
```bash
cortex edit "github-work" --tags "work,dev,updated"
```

**Prompts:**
- Master password: [hidden or cached]
- New password (Enter to keep current): [hidden]
- Confirm new password: [if password changed]
- New description (Enter to keep current): [text]

**Output:** `Edited for 'github-work'.` or `No changes made to 'github-work'.`

**Behavior:**
- Empty inputs keep current values
- Tags flag replaces all existing tags
- No-op detected automatically

### Deleting Entries
```bash
cortex delete "old-account"
```

**Output:** `Deleted 'old-account'.` or `Account 'old-account' not found.`

**Restrictions:** Cannot delete system entries (names starting with `__`)

### Searching Entries

**Basic search:**
```bash
cortex find "github"
```

**Advanced search:**
```bash
cortex find "aws" --ignore-case --names-only
```

**Output:**
```
Found 2 match(es) for: github

Entry: github-work
  >> Matches: name and tags
  Description: Work GitHub account for project X
  Tags: work, dev, critical

Entry: github-personal
  >> Matches: description
  Description: Personal GitHub for side projects
  Tags: personal, dev
```

**Options:**
- `--ignore-case, -i`: Case-insensitive matching
- `--names-only, -n`: Search only entry names
- Supports regex patterns (automatically escaped for literal search)
- Shows first 20 results
- Indicates match location (name/description/tags)

### Tag Management

**List all tags with counts:**
```bash
cortex tag list
```

**Output:**
```
Tags:
  work (5)
  dev (4)
  production (3)
  personal (2)
  critical (2)
```

**Add tags to entry:**
```bash
cortex tag add "github-work" "urgent,security"
```

**Output:** `Added 2 tag(s) to 'github-work'`

**Remove tags from entry:**
```bash
cortex tag remove "github-work" "urgent"
```

**Output:** `Removed 1 tag(s) from 'github-work'`

**Tag Rules:**
- Maximum 20 tags per entry
- Maximum 30 characters per tag
- Alphanumeric, hyphens, and underscores only
- Automatically normalized (lowercase, sorted, deduplicated)
- Case-insensitive duplicate detection

### Password Generation

**Default generation (16 chars, all types):**
```bash
cortex pass
```

**Custom generation:**
```bash
cortex pass --length 20 --count 3
```

**Selective character types:**
```bash
cortex pass --length 12 --uppercase --digits
```

**Options:**
- `--length, -l`: Password length (default: 16, min: 4, max: 128)
- `--count, -c`: Number of passwords (default: 1, range: 1-50)
- `--uppercase, -u`: Include uppercase letters
- `--lowercase, -w`: Include lowercase letters
- `--digits, -d`: Include digits
- `--special, -s`: Include special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)

**Default behavior:** If no flags specified, all character types enabled

### Export Database

**Export all passwords:**
```bash
cortex export
```

**Export template:**
```bash
cortex export --template
```

**Process:**
1. Master password authentication
2. Security warning display
3. Confirmation: "I understand this exports passwords in plain text"
4. Export to `cortex_export_[timestamp].json`
5. File permissions set to 0600 (Unix)

**Output format (JSON):**
```json
{
  "version": "3.0.0",
  "timestamp": 1699999999,
  "entries": [
    {
      "name": "github-work",
      "password": "your_secure_password_123",
      "description": "Work GitHub account",
      "tags": ["work", "dev", "critical"]
    }
  ]
}
```

**Template output** (`cortex_template.json`):
```json
{
  "version": "3.0.0",
  "timestamp": 1699999999,
  "entries": [
    {
      "name": "heisenberg",
      "password": "1AmTh3D4ng3r!",
      "description": "Say my name - I am the one who knocks",
      "tags": ["work", "critical"]
    }
  ]
}
```

### Import Database

**Basic import:**
```bash
cortex import "backup.json"
```

**Import with overwrite:**
```bash
cortex import "backup.json" --overwrite
```

**Process:**
1. File validation and parsing
2. Entry validation (names, passwords, descriptions, tags)
3. Master password authentication
4. Batch import with progress
5. Automatic rollback on failure

**Validation rules:**
- Names: Non-empty, no `__` prefix
- Passwords: Minimum 4 characters
- Descriptions: Maximum 500 characters, no password fragments
- Tags: Maximum 20 per entry, valid format

**Output:**
```
Import Summary:
  Version: 3.0.0
  Timestamp: 1699999999
  Total entries: 15

Imported: entry1
Imported: entry2
Skipping 'entry3': already exists (use --overwrite to replace)

Import completed:
  Imported: 12
  Skipped: 2
  Failed: 1
```

**Rollback:** Automatic on errors, restores original entries

### Master Password Management

**Reset master password:**
```bash
cortex reset
```

**Process:**
1. Current master password authentication
2. Automatic backup creation
3. New password with complexity validation
4. Re-encryption of all entries with new password
5. Verification data update

**Output:** `Master password reset successfully.`

**Security:** All data re-encrypted, old sessions invalidated

### Session Management

**View current configuration:**
```bash
cortex config show
```

**Output:**
```
Current Configuration:
  Session timeout: 480 seconds (8 minutes)
```

**Set session timeout:**
```bash
cortex config set-timeout 1800
```

**Output:** `Session timeout set to 1800 seconds (30 minutes)`

**Range:** 60 seconds (1 minute) to 86400 seconds (24 hours)

**Clear session manually:**
```bash
cortex lock
```

**Output:** `Session cleared. You will need to authenticate again.`

**Session behavior:**
- Cached after first successful authentication
- Validated on each command
- Auto-expires after configured timeout
- Machine-bound (cannot transfer between systems)
- Secure file storage with 0600 permissions

### Database Destruction
```bash
cortex purge
```

**Security verification:**
1. Master password authentication
2. Math puzzle: "This will permanently delete all stored passwords!"
3. Equation example: `(47 + 23) * 3`
4. Answer validation

**Output:** `Database purged.`

**Effect:** Permanent deletion of all data, backups preserved

## Common Error Scenarios

```bash
# Database already exists
cortex init
# Output: "Database already exists. Use a different path or remove existing database."

# Database not initialized
cortex list
# Output: "Database not initialized. Use 'init' command."

# Duplicate entry creation
cortex create "existing-account"
# Output: "Account already exists. Use 'edit' to update or choose a different name."

# Weak master password
cortex init
# Master password: weak123
# Output: "Error: Your password needs improvement.
#          Missing: uppercase letter, special character"

# Short account password
cortex create "test"
# Password to store: abc
# Output: "Error: Password must be at least 4 characters"

# Password in description
cortex create "secure-app"
# Password: mySecretPass123
# Description: My password is mySecretPass123
# Output: "Error: Description cannot contain the password or parts of it."

# Invalid session timeout
cortex config set-timeout 30
# Output: "Error: Session timeout must be at least 60 seconds (1 minute)"

# Invalid clipboard timeout
cortex get "account" --clip 600
# Output: "Error: The time to be distracted is only allowed to be between 3 and 540 seconds"

# Invalid tags
cortex create "test" --tags "tag1,tag with space,tag3"
# Output: "Error: Tags can only contain alphanumeric characters, hyphens, and underscores"

# Too many tags
cortex create "test" --tags "tag1,tag2,...,tag21"
# Output: "Error: Maximum 20 tags allowed"

# Entry not found
cortex delete "nonexistent"
# Output: "Account 'nonexistent' not found."

# System entry protection
cortex delete "__init__"
# Output: "Error: Cannot delete system entries"

# Empty search pattern
cortex find ""
# Output: "Error: Search pattern cannot be empty"

# Import validation errors
cortex import "invalid.json"
# Output:
# Validation errors:
#   - entry1: Password must be at least 4 characters
#   - entry2: Description too long
```

## Configuration

### Database Location
- **Linux**: `~/.config/cortex/.password-store`
- **macOS**: `~/Library/Application Support/cortex/.password-store`
- **Windows**: `%APPDATA%/cortex/.password-store`

### Session File Location
- **Linux**: `~/.cache/cortex/.cortex_session`
- **macOS**: `~/Library/Caches/cortex/.cortex_session`
- **Windows**: `%LOCALAPPDATA%/cortex/.cortex_session`

### Backup Location
Database backups stored in: `[database_dir]/backups/`
- Automatic backup before `reset` command
- Automatic backup on initialization
- Keeps last 5 backups
- Named: `backup_[timestamp].db`

### File Permissions (Unix)
- Database directory: `0700` (owner only)
- Database files: `0600` (owner read/write)
- Session file: `0600` (owner read/write)
- Export files: `0600` (owner read/write)

## Security Considerations

### Encryption
- **Algorithm**: ChaCha20-Poly1305 AEAD
- **Key Size**: 256 bits
- **Nonce Size**: 96 bits (12 bytes), unique per encryption
- **KDF Iterations**: 600,000 (BLAKE3)
- **Session KDF**: 300,000 iterations (lighter for performance)

### Hardware Binding
- **Purpose**: Prevent database transfer attacks
- **Components**: CPU brand, system identifiers
- **Effect**: Database cannot be decrypted on different hardware
- **Warning**: Hardware changes require export before migration

### Memory Security
- **SecureString**: Automatic zeroing on drop
- **SessionData**: Zeroize implementation for all sensitive fields
- **Password Prompts**: Hidden input, no echo
- **Clipboard**: Automatic clearing after timeout

### Input Validation
- **Master Password**: Min 8 chars, complexity requirements
- **Account Password**: Min 4 chars
- **Description**: Max 500 chars, no password fragments
- **Tags**: Max 20 per entry, 30 chars each, valid format
- **Search Pattern**: Max 100 chars, max 10,000 entries processed

### Session Security
- **Encryption**: ChaCha20-Poly1305 with unique session key
- **Machine Binding**: SHA256 hash of CPU brand
- **Timeout**: Configurable (60s - 24h)
- **Max Age**: Hard limit of 24 hours
- **Failed Attempts**: Max 3 before session clear
- **File Security**: Secure overwrite before deletion

### Export Security
- **Confirmation**: Plain text warning required
- **File Permissions**: Restricted to owner (Unix)
- **Temporary Files**: Written to .tmp first, then renamed
- **Error Handling**: Failed exports cleaned up

### Import Security
- **Validation**: Comprehensive before any database changes
- **Rollback**: Automatic on failure
- **Progress**: Real-time feedback
- **Batch Safety**: Transactional behavior

## Password Security Requirements

### Master Password
- **Minimum**: 8 characters
- **Complexity**: At least 3 of 4 types:
  - Lowercase letters (a-z)
  - Uppercase letters (A-Z)
  - Digits (0-9)
  - Special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)
- **Validation**: Checked during `init` and `reset`

### Account Passwords
- **Minimum**: 4 characters
- **Maximum**: No limit (practical limit: 128 for input)
- **Restriction**: Cannot appear in description field
- **Fragment Detection**: Sliding window algorithm for partial matches

## Dependencies

### Core Security
- `blake3` (1.5.x): High-performance cryptographic hashing
- `chacha20poly1305` (0.10.x): Authenticated encryption
- `rand` (0.8.x): Cryptographically secure RNG
- `zeroize` (1.7.x): Secure memory clearing

### Storage
- `sled` (0.34.x): Embedded database engine
- `bincode` (1.3.x): Binary serialization
- `serde` (1.0.x): Serialization framework
- `serde_json` (1.0.x): JSON support

### System
- `sysinfo` (0.30.x): Hardware information
- `dirs` (5.0.x): Standard directory locations
- `fs2` (0.4.x): File locking (Unix)

### CLI
- `clap` (4.5.x): Command-line parsing with derive macros
- `rpassword` (7.3.x): Secure password input
- `copypasta` (0.10.x): Clipboard management
- `ctrlc` (3.4.x): Signal handling

### Utilities
- `regex` (1.10.x): Pattern matching

## Technical Specifications

### Cryptography
- **Cipher**: ChaCha20-Poly1305
- **Key Size**: 256 bits
- **Nonce**: 96 bits (12 bytes), crypto-random
- **Tag**: 128 bits (16 bytes), authenticated
- **Hash**: BLAKE3, 256-bit output
- **KDF**: BLAKE3^600000(password || salt || hardware_id)
- **Session KDF**: BLAKE3^300000(hardware || constant || salt)

### Storage
- **Engine**: Sled embedded key-value store
- **Format**: Binary (bincode serialization)
- **System Entries**: Prefixed with `__`
  - `__init__`: Verification data
  - `__salt__`: 32-byte master salt
  - `__config__`: Serialized configuration
- **Backup Retention**: Last 5 backups

### Limits
- **Password Length**: 4-128 characters (input), unlimited (storage)
- **Description**: 500 characters
- **Tags**: 20 per entry, 30 characters each
- **Search Pattern**: 100 characters
- **Search Results**: First 20 displayed
- **Search Processing**: Max 10,000 entries
- **Session Timeout**: 60 seconds to 24 hours
- **Max Session Age**: 24 hours (hard limit)
- **Clipboard Timeout**: 3-540 seconds
- **Password Generation**: 4-128 characters, 1-50 count
- **Import Batch**: Unlimited with validation

### Performance
- **KDF Speed**: ~300ms for 600,000 iterations (varies by CPU)
- **Session KDF**: ~150ms for 300,000 iterations
- **Encryption**: < 1ms per entry
- **Database**: O(log n) lookups
- **Search**: O(n) with early termination
- **Export**: Buffered writes (64KB buffer), 1000-entry progress

## Command Reference

| Command | Purpose | Required Args | Optional Args |
|---------|---------|---------------|---------------|
| `init` | Initialize database | None | None |
| `create <name>` | Create entry | name | --tags \<tags\> |
| `get <name>` | Retrieve entry | name | --clip [seconds] |
| `list` | List all entries | None | --tags (deprecated) |
| `delete <name>` | Delete entry | name | None |
| `edit <name>` | Edit entry | name | --tags \<tags\> |
| `find <pattern>` | Search entries | pattern | -i, -n |
| `tag list` | List all tags | None | None |
| `tag add <name> <tags>` | Add tags | name, tags | None |
| `tag remove <name> <tags>` | Remove tags | name, tags | None |
| `pass` | Generate passwords | None | -l, -c, -u, -w, -d, -s |
| `export` | Export database | None | --template |
| `import <file>` | Import from JSON | file | --overwrite |
| `reset` | Change master password | None | None |
| `config show` | Show configuration | None | None |
| `config set-timeout <sec>` | Set session timeout | seconds | None |
| `lock` | Clear session | None | None |
| `purge` | Destroy database | None | None |

## Troubleshooting

### Session Issues
**Problem**: "Authentication failed" despite correct password
**Solution**: Clear session and try again
```bash
cortex lock
cortex list
```

**Problem**: Session expires too quickly
**Solution**: Increase timeout
```bash
cortex config set-timeout 3600  # 1 hour
```

### Hardware Issues
**Problem**: "Decryption failed" after hardware change
**Solution**: Export from backup, reinitialize, and import
```bash
# On old system:
cortex export

# On new system:
cortex init
cortex import cortex_export_[timestamp].json
```

### Import Errors
**Problem**: Import validation errors
**Solution**: Review JSON format and validation rules
```bash
# Generate template for reference
cortex export --template

# Check validation errors in output
cortex import file.json
```

### Permission Issues
**Problem**: "Permission denied" on Unix
**Solution**: Check file permissions
```bash
chmod 700 ~/.config/cortex
chmod 600 ~/.config/cortex/.password-store/*
```

## Best Practices

### Master Password
- Use a unique, strong passphrase
- Never store in plain text
- Use password manager for backup (not Cortex itself)
- Change periodically with `reset` command

### Session Management
- Set appropriate timeout for your workflow
- Use `lock` when leaving workstation
- Shorter timeouts for shared systems
- Longer timeouts for personal, secure systems

### Organization
- Use descriptive entry names
- Add meaningful descriptions
- Tag entries consistently
- Create tag hierarchy: `work-dev`, `work-prod`, `personal-email`

### Backups
- Export regularly to encrypted external storage
- Test import process periodically
- Keep backups on separate media
- Automate with scripts if needed

### Security
- Use clipboard mode to avoid terminal history
- Clear clipboard manually with Ctrl+C if needed
- Don't share export files
- Secure export files immediately (encrypt or delete)
- Use `purge` to completely remove database

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup
```bash
git clone https://github.com/naseridev/cortex.git
cd cortex
cargo build
cargo test
```

## Author

Nima Naseri <nerdnull@proton.me>

---

**Critical Warning**: This software binds encryption keys to hardware characteristics. Transferring the database to different hardware will result in permanent data loss. Always export your passwords before hardware changes, system reinstalls, or major updates.

**Security Notice**: The export function creates plain text files containing all passwords. Secure or delete these files immediately after use. Set file permissions to 0600 on Unix systems and store in encrypted containers.

**Session Warning**: Session files contain encrypted master passwords. While encrypted and machine-bound, compromise of the session file combined with the same machine access could allow unauthorized access. Use `lock` command when leaving your system unattended.
