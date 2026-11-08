# Cortex Password Manager - User Guide

This guide covers everyday commands, configuration options, and cloud synchronization workflows for Cortex v4.0.0.

## Table of Contents

- [Core Concepts](#core-concepts)
- [Account Management](#account-management)
  - [Creating Accounts](#creating-accounts)
  - [Listing Accounts](#listing-accounts)
  - [Switching Accounts](#switching-accounts)
  - [Renaming Accounts](#renaming-accounts)
  - [Resetting Master Passwords](#resetting-master-passwords)
  - [Deleting Accounts](#deleting-accounts)
  - [Dumping and Restoring Vaults](#dumping-and-restoring-vaults)
  - [Exporting and Importing CSVs](#exporting-and-importing-csvs)
- [Vault Operations](#vault-operations)
  - [Adding Entries](#adding-entries)
  - [Retrieving Passwords](#retrieving-passwords)
  - [Editing Entries](#editing-entries)
  - [Deleting Entries](#deleting-entries)
  - [Listing Entries](#listing-entries)
  - [Searching Entries](#searching-entries)
  - [Managing Tags](#managing-tags)
  - [Locking Sessions](#locking-sessions)
- [Password Generation](#password-generation)
- [Cloud Synchronization](#cloud-synchronization)
  - [Supported Providers](#supported-providers)
  - [Setting Up Remotes](#setting-up-remotes)
  - [Pushing to Cloud](#pushing-to-cloud)
  - [Pulling from Cloud](#pulling-from-cloud)
  - [Two-Way Sync](#two-way-sync)
  - [Managing Remotes](#managing-remotes)
- [Security Specifications](#security-specifications)
- [Command Reference](#command-reference)
- [Troubleshooting](#troubleshooting)

---

## Core Concepts

* **Accounts**: Every account is an independent database file. Each has its own master password, Argon2id salt, and integrity records.
* **Active Account**: One account is marked active at a time. Commands default to this account unless you pass an explicit account flag.
* **Session Cache**: When you unlock your vault, Cortex saves the derived key in your operating system keyring for 8 minutes (480 seconds). Subsequent commands reuse this key without prompting.
* **Integrity Manifest**: A BLAKE3 hash covers every key and value in the database. If a file gets corrupted, tampered with, or rolled back, Cortex stops execution to prevent loading unsafe data.

---

## Account Management

### Creating Accounts
```bash
cortex account create
cortex account create personal
```
Creates a new vault database. You will be prompted for a master password. It must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.

### Listing Accounts
```bash
cortex account list
```
Prints all registered accounts on this system. The active account has an asterisk next to it.

### Switching Accounts
```bash
cortex account switch work
```
Changes the default account for subsequent vault and sync operations. It also clears any active session keys from the keyring.

### Renaming Accounts
```bash
cortex account edit
cortex account edit current_name new_name
```
Renames an existing account, moves the database file safely, and updates internal registry entries.

### Resetting Master Passwords
```bash
cortex account reset
cortex account reset personal
```
Prompts for your old password, asks for a new password, and re-encrypts every entry, description, and tag set in that account. Existing binary dumps created earlier will still need the master password that was active when they were made.

### Deleting Accounts
```bash
cortex account delete personal
```
Prompts for your master password and asks you to solve a short math problem to confirm. Once confirmed, it deletes the database file permanently.

### Dumping and Restoring Vaults

**Creating an encrypted dump:**
```bash
cortex account dump
```
Creates an encrypted file named `dump_<timestamp>.bin` in your current working directory.

**Restoring from a dump:**
```bash
cortex account restore dump_00000000000000000001.bin
```
Replaces the active database with the contents of the dump file. You need to enter the master password that was used when creating that specific dump.

### Exporting and Importing CSVs

**Exporting to plaintext CSV:**
```bash
cortex account export
```
Prompts for authentication and warns you that passwords will be written in plain text. The exported file (`cortex_export_<random>.csv`) is created with owner-only read permissions (`0600` on Unix).

**Importing entries:**
```bash
cortex account import backup.csv
cortex account import backup.csv --overwrite
```
Reads a CSV file, checks that all entries meet character and length requirements, and writes them to the current account. Existing entries are skipped unless you include the `--overwrite` flag.

---

## Vault Operations

### Adding Entries
```bash
cortex vault create "github"
cortex vault create "aws-console" --tags "work,cloud,devops"
```
Prompts:
1. Password to store (visible input so you can verify what you type, followed by confirmation)
2. Optional description (up to 500 characters)

Cortex verifies that descriptions do not accidentally contain parts of the password you are storing.

### Retrieving Passwords
```bash
# Copies password to clipboard and wipes it after 60 seconds:
cortex vault get "github"

# Prints password directly to terminal:
cortex vault get "github" --show
```

### Editing Entries
```bash
cortex vault edit "github"
cortex vault edit "github" --tags "work,infra"
```
Prompts for a new password and description. Press Enter on any prompt to keep the current value. Passing `--tags` replaces all existing tags on the entry.

### Deleting Entries
```bash
cortex vault delete "github"
```
Deletes the entry and creates a deletion tombstone with a logical timestamp. This prevents other devices from recreating the entry during sync.

### Listing Entries
```bash
cortex vault list
cortex vault list --tags
```
Lists every entry name and description in the active account. Add `--tags` to display tags alongside each item.

### Searching Entries
```bash
cortex vault find "database"
cortex vault find "prod.*key" --ignore-case
cortex vault find "aws" --names-only
```
Runs a regex search over entry names, decrypted notes, and tags. Use `--names-only` to skip checking descriptions and tags.

### Managing Tags
```bash
cortex vault tag list
cortex vault tag add "github" "production,vcs"
cortex vault tag remove "github" "vcs"
```
Tag guidelines:
* Tags are converted to lowercase, trimmed, deduplicated, and sorted automatically.
* Allowed characters: letters, numbers, hyphens, and underscores.
* Maximum length: 30 characters per tag, up to 20 tags per entry.

### Locking Sessions
```bash
cortex vault lock
```
Deletes the cached session key from your system keyring. The next vault command will ask for your master password again.

---

## Password Generation

```bash
# Default: 16 characters with uppercase, lowercase, numbers, and symbols
cortex pass

# Set specific length and generate multiple passwords:
cortex pass --length 24 --count 5

# Limit character sets:
cortex pass --length 16 --uppercase --lowercase --digits
cortex pass --length 20 --digits --special
```

Flags:
* `-l, --length`: Password length (8 to 128)
* `-c, --count`: How many passwords to print (1 to 50)
* `-u, --uppercase`: Include A-Z
* `-w, --lowercase`: Include a-z
* `-d, --digits`: Include 0-9
* `-s, --special`: Include punctuation and symbols

---

## Cloud Synchronization

Cortex lets you sync encrypted snapshots to remote servers or local drives. The remote server only sees encrypted data; your credentials and passwords never leave your machine in plain text.

### Supported Providers

| Provider | Name Flag | Required Arguments |
|---|---|---|
| Google Drive | `gdrive` | Access token, optional refresh token and client ID |
| Dropbox | `dropbox` | Access token, optional refresh token and client ID |
| OneDrive | `onedrive` | Access token, optional client ID |
| Nextcloud | `nextcloud` | Server URL, Username, App password |
| AWS S3 or Compatible | `s3` | Bucket, Region, Access Key ID, Secret Key, optional Endpoint |
| Google Cloud Storage | `gcs` | Bucket, OAuth2 token, optional Endpoint |
| Azure Blob Storage | `azblob` | Container, Storage Account, Account Key |
| Backblaze B2 | `b2` | Bucket, Bucket ID, Application Key ID, Application Key |
| Alibaba Cloud OSS | `oss` | Bucket, Endpoint, Access Key ID, Secret |
| Tencent Cloud COS | `cos` | Bucket, Endpoint, Secret ID, Secret Key |
| pCloud | `pcloud` | Endpoint URL, Username, Password |
| Yandex Disk | `yandex` | OAuth token |
| Koofr | `koofr` | Endpoint URL, Email, App password |
| WebDAV | `webdav` | Server URL, Username, Password |
| Local Directory or NAS | `local` | Directory path |

### Setting Up Remotes

```bash
# Google Drive:
cortex cloud add gdrive --name "mydrive" --root "/cortex"

# Amazon S3:
cortex cloud add s3 --name "backup-s3" --bucket "vault-bucket" --region "us-east-1"

# Nextcloud:
cortex cloud add nextcloud --url "https://cloud.example.com" --username "alice"

# Local folder, external drive, or network share:
cortex cloud add local --path "/mnt/backup/cortex" --name "nas"
```

Credentials are saved in your system keyring. If your system does not have a working keyring, Cortex prompts for a dedicated passphrase to seal your cloud credentials into `cloud.bin`.

### Pushing to Cloud
```bash
cortex cloud push
cortex cloud push --remote "backup-s3"
cortex cloud push --force
```
Uploads your local vault. Cortex checks whether the remote copy changed since your last sync. If another device pushed changes in the meantime, the upload stops to avoid overwriting them. Use `--force` only if you deliberately want to overwrite the remote vault.

### Pulling from Cloud
```bash
cortex cloud pull
cortex cloud pull --remote "backup-s3" --account "work"
cortex cloud pull --overwrite
```
Downloads the remote vault and asks for that vault master password. It updates your local database and sync history records.

### Two-Way Sync
```bash
cortex cloud sync
cortex cloud sync --remote "backup-s3"
```
Reconciles changes between your local database and the cloud:
1. Compares logical clocks and hashes on both sides.
2. Identifies new, edited, and deleted entries.
3. Merges changes using deterministic rules (newer modification time wins; deletions win if timestamps are equal).
4. Commits the merged data locally and uploads the updated vault to the remote target.

### Managing Remotes
```bash
# Check sync status:
cortex cloud status

# List remotes:
cortex cloud list

# Set default remote:
cortex cloud default "backup-s3"

# Remove a remote and wipe its credentials:
cortex cloud remove "backup-s3"
```

---

## Security Specifications

* **Key Derivation**: Argon2id version 0x13 (64 MiB memory, 3 iterations, 1 lane).
* **Encryption**: ChaCha20-Poly1305 AEAD.
* **Nonces**: 96-bit (12-byte) cryptographically secure random values generated from OS entropy for every field.
* **Integrity**: BLAKE3 keyed hash covering all entries, tombstones, and logical clock records under the `__manifest__` entry.
* **File Obfuscation**: Account database files use the BLAKE3 hex digest of the account name as their filename (`<blake3_hex>.redb`).
* **Permissions**:
  * Unix: `0700` for directories, `0600` for files.
  * Windows: Restricted to the active user account via `icacls`.
* **Session Lifetime**: 8 minutes (480 seconds) from last unlock.

---

## Command Reference

| Section | Command | Action |
|---|---|---|
| `account` | `create [name]` | Initialize a new account |
| `account` | `list` | Print all registered accounts |
| `account` | `switch [name]` | Set the default active account |
| `account` | `edit [name] [new_name]` | Rename an account |
| `account` | `delete [name]` | Remove an account and delete its file |
| `account` | `reset [name]` | Change master password and re-encrypt vault |
| `account` | `export` | Export entries to unencrypted CSV |
| `account` | `import <file> [--overwrite]` | Import entries from CSV |
| `account` | `dump` | Write an encrypted binary snapshot |
| `account` | `restore <file>` | Restore from an encrypted binary snapshot |
| `vault` | `create <name> [-t tags]` | Store a new password |
| `vault` | `get <name> [--show]` | Copy password to clipboard or print to terminal |
| `vault` | `edit <name> [-t tags]` | Update an existing password, note, or tag set |
| `vault` | `delete <name>` | Delete an entry and record a tombstone |
| `vault` | `list [-t]` | Display stored entries |
| `vault` | `find <pattern> [-i] [-n]` | Regex search over names, notes, and tags |
| `vault` | `tag list` | Print all tags with entry counts |
| `vault` | `tag add <name> <tags>` | Add comma-separated tags to an entry |
| `vault` | `tag remove <name> <tags>` | Remove tags from an entry |
| `vault` | `lock` | Clear session key from OS keyring |
| `cloud` | `add <provider>` | Add and configure a cloud storage remote |
| `cloud` | `sync [-r remote] [-a account]` | Two-way merge with a cloud remote |
| `cloud` | `push [-r remote] [-a account] [-f]` | Upload vault to a cloud remote |
| `cloud` | `pull [-r remote] [-a account] [-o]` | Download vault from a cloud remote |
| `cloud` | `list` | Show configured cloud remotes |
| `cloud` | `status [-r remote] [-a account]` | Check synchronization status |
| `cloud` | `default <name>` | Choose default cloud remote |
| `cloud` | `remove <name>` | Delete remote and clear stored credentials |
| `pass` | `pass [-l len] [-c count] [-u] [-w] [-d] [-s]` | Generate random passwords |

---

## Troubleshooting

### Database Integrity Check Failed
**Message:** `Database integrity check failed. Stored data was modified, replaced or removed outside of cortex.`
**Cause:** The database file was edited externally, corrupted on disk, or partially overwritten.
**Solution:** Restore your database from your most recent binary dump using `cortex account restore <dump_file.bin>`.

### Repeated Password Prompts
**Issue:** Cortex asks for your master password on every single command instead of using session caching.
**Cause:** Your desktop session does not have an unlocked secret service or keychain daemon (common in headless SSH sessions or minimal window managers).
**Solution:** Run `cortex vault lock` to reset the session state, or unlock your keyring daemon (such as `gnome-keyring` or `kwallet`) when logging in.

### Clock Skew Warning During Sync
**Message:** `Warning: remote holds timestamps X seconds ahead of this device's clock.`
**Cause:** Two devices syncing the same vault have system clocks that are out of sync by more than five minutes.
**Solution:** Enable NTP time synchronization on each computer to keep their clocks aligned.