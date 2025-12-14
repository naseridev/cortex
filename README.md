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

## Quick Start

Initialize the database:
```bash
cortex init
```

Create your first password:
```bash
cortex create "github-work" --tags "work,dev"
```

Retrieve a password:
```bash
cortex get "github-work" --clip
```

List all entries:
```bash
cortex list
```

## Documentation

For detailed usage instructions, command reference, and advanced features, see the [User Guide](README.wiki.md).

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
```
```bash
cd cortex
```
```bash
cargo build
```

## Author

Nima Naseri <nerdnull@proton.me>

---

**Critical Warning**: This software binds encryption keys to hardware characteristics. Transferring the database to different hardware will result in permanent data loss. Always export your passwords before hardware changes, system reinstalls, or major updates.

**Security Notice**: The export function creates plain text files containing all passwords. Secure or delete these files immediately after use. Set file permissions to 0600 on Unix systems and store in encrypted containers.

**Session Warning**: Session files contain encrypted master passwords. While encrypted and machine-bound, compromise of the session file combined with the same machine access could allow unauthorized access. Use `lock` command when leaving your system unattended.
