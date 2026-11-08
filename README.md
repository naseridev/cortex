# Cortex Password Manager

Cortex is a secure, multi-account password manager written in Rust. It uses Argon2id for key derivation, ChaCha20-Poly1305 for authenticated encryption, BLAKE3 for tamper detection, and OpenDAL for cloud sync across multiple storage backends.

## Overview

Cortex gives you an encrypted command-line vault that stays responsive and easy to script. It protects against offline attacks by combining modern primitives: Argon2id hashes your master password, ChaCha20-Poly1305 encrypts entries with associated data, and BLAKE3 manifests detect any external edits or rollbacks to the database file.

Version 4.0.0 separates data into isolated accounts, adds encrypted full-database dumps, supports plaintext CSV imports and exports, clears your clipboard automatically, and syncs encrypted vaults across 15 cloud providers.

## Key Features

### Security and Cryptography
* **Argon2id Key Derivation**: Configured with 64 MiB memory, 3 iterations, and 1 lane to protect against GPU and ASIC cracking.
* **ChaCha20-Poly1305 AEAD**: Every password, description, and tag list is encrypted with an authenticated cipher. Entry names are bound as associated data to prevent swapping ciphertext between entries.
* **Database Integrity**: A keyed BLAKE3 manifest recalculates on every commit. If someone alters, deletes, or rolls back records outside Cortex, the database refuses to open.
* **Memory Safety**: Sensitive buffers, decrypted passwords, and master keys implement automatic zeroing on drop through the zeroize crate.
* **Keyring Sessions**: Once unlocked, Cortex caches the derived key in your operating system credential store (Linux Secret Service, macOS Keychain, or Windows Credential Manager) for 8 minutes so you do not have to type your master password repeatedly.
* **Throttling**: Failed login attempts trigger exponential backoff delays to stop automated guessing in the terminal.

### Multi-Account Vaults
* **Account Isolation**: Each account has its own master password, cryptographic salt, and separate storage file.
* **Hidden File Names**: Database files are stored using the BLAKE3 hash of the account name, keeping names private on disk.
* **Account Controls**: Create, switch, rename, delete, and reset accounts directly from the CLI.
* **ACID Storage**: Embedded storage runs on redb for transactional safety and crash recovery.

### Entry and Tag Management
* **Tags**: Add up to 20 normalized tags per entry for easy filtering.
* **Regex Search**: Search across entry names, decrypted notes, and tags with optional case insensitivity.
* **Password Generator**: Generate passwords using customizable character sets (uppercase, lowercase, digits, and special characters).
* **Clipboard Clearing**: Copies secrets directly to your clipboard and wipes them after 60 seconds (or immediately if you press Ctrl+C).

### Backups and Sync
* **Encrypted Dumps**: Export binary snapshot files (.bin) containing the full database state.
* **CSV Interchange**: Import and export standard CSV files for migration to or from other tools.
* **Tombstone Tracking**: Deleted entries leave timestamps so cloud sync operations do not resurrect them later.
* **Multi-Cloud Sync**: Sync directly with Google Drive, Dropbox, OneDrive, Nextcloud, AWS S3, Google Cloud Storage, Azure Blob, Backblaze B2, Alibaba OSS, Tencent COS, pCloud, Yandex Disk, Koofr, WebDAV, or local storage directories.

## Architecture

The codebase is split into focused modules:

* `storage`: Database engine logic (redb), CRUD operations, metadata, maintenance, snapshots, and account registration.
* `security`: Argon2id derivation, ChaCha20-Poly1305 AEAD, master password checks, throttling, and keyring sessions.
* `domain`: Data types (PasswordEntry, ExportEntry), validation rules, tag normalization, and limits.
* `system`: OS-level file permission handling (0600 and 0700 permissions on Unix, explicit ACLs on Windows) and system clocks.
* `cloud`: Client backends, provider settings, and the multi-device sync engine.
* `formats`: Binary dump files and CSV encoding or decoding.
* `commands`: CLI subcommand execution for accounts, vaults, cloud sync, and password generation.
* `ui`: Terminal prompts, clipboard workers, math puzzles, and CLI argument parsing.

## Installation

### Prerequisites
* Linux, macOS, or Windows
* Rust 1.90.0 or later (Rust 2024 Edition)

### Build from Source

```bash
git clone https://github.com/naseridev/cortex.git
cd cortex
cargo build --release
```

Install the compiled binary into your cargo path:
```bash
cargo install --path .
```

Confirm that the installation succeeded:
```bash
cortex --version
```

## Quick Start

Create your first account:
```bash
cortex account create
```

Store a password:
```bash
cortex vault create "github" --tags "work,dev"
```

Copy the password to your clipboard (clears automatically in 60 seconds):
```bash
cortex vault get "github"
```

Print the password directly in the terminal:
```bash
cortex vault get "github" --show
```

List all stored entries:
```bash
cortex vault list --tags
```

Lock your session immediately:
```bash
cortex vault lock
```

## Documentation

For full command documentation, cloud configuration steps, and operational guides, see the [User Guide](README.wiki.md).

## Author

Nima Naseri <nerdnull@proton.me>