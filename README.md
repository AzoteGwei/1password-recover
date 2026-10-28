# 1Password SQLite Recover & 1PUX Exporter

Extract and decrypt passwords and items from a local `1password.sqlite` database and export them into a standard **`.1pux`** (1Password Unencrypted Export) package.

This package can be imported directly into **1Password 8**, **Bitwarden**, **KeePassXC**, or **Apple Passwords**.

> **No Docker Required**. Modernized to Python 3 with [uv](https://docs.astral.sh/uv/) for instant execution.
> Safe credential input using masked passwords (no plaintext leakage in terminal history).

---

## 🚀 Quick Start (with `uv`)

### 1. Copy your `1password.sqlite` database
Make sure **1Password is completely closed/quit** before copying the file. This ensures SQLite flushes the Write-Ahead Log (WAL) into the main single database file.

On macOS (1Password 7 / 8):
```bash
# 1. Completely quit 1Password
killall "1Password" 2>/dev/null

# 2. Copy the database
cp ~/Library/Group\ Containers/2BUA8C4S2C.com.1password/Library/Application\ Support/1Password/Data/1password.sqlite .
```

On Windows (1Password 8):
```powershell
# In PowerShell:
Copy-Item "$env:LOCALAPPDATA\1password\data\1password.sqlite" .
```

### 2. Run the recovery tool

Using `uv`:
```bash
uv run recover-op
```

Or using native Python 3:
```bash
python -m recover_op.cli
# or
python recover_op/get_items.py
```

### 3. Enter your credentials
The tool will automatically detect if multiple accounts exist in the database, allow you to select which account to decrypt (skipping any Passkey-only accounts), and securely prompt for your credentials without echoing characters:
```text
[*] Found 1Password database: ./1password.sqlite (4.25 MB)
----------------------------------------------------------------------
[*] Discovered 2 accounts in database:
    [1] Personal (user@gmail.com | https://my.1password.com | UUID: 2BUA8C...)
    [2] Work Passkey Account (user@company.com | https://company.1password.com)

Select account to decrypt [1-2] (default: 1): 1

[+] Active account: Personal (user@gmail.com)
Enter Secret Key (e.g. A3-xxxxxx-xxxxxx-...): 
Enter Master Password: 
Enter Account Email (press Enter for 'user@gmail.com'): 

[*] Deriving keys and decrypting vaults...
[+] Successfully decrypted 1 vault(s) and 182 item(s)!
    - Vault 1: 'Personal' -> 182 items

[+] Exported 1PUX package: ./recovered_Personal_1740000000.1pux
[*] You can now directly import this .1pux file into:
    - 1Password 8 (File -> Import -> 1Password Unencrypted Export)
    - KeePassXC (Database -> Import -> 1Password .1pux)
    - Bitwarden (Tools -> Import Data -> 1Password (1pux))
```

---

## 🛠️ CLI Options

You can also pass arguments directly or via environment variables for automation:

```bash
uv run recover-op --help
```

```text
options:
  -h, --help            show this help message and exit
  --db, -d DB           Path to 1password.sqlite database file (default: 1password.sqlite)
  --account, -a ACC     Account to decrypt by index (e.g. 1, 2), UUID, or email
  --output, -o OUTPUT   Path for output .1pux file (default: recovered_<timestamp>.1pux)
  --email, -e EMAIL     1Password account email address
  --secret-key, -s KEY  1Password account Secret Key (A3-...)
  --password, -p PWD    1Password account Master Password
  --mode {auto,sqlite,raw}
                        Extraction strategy: 'sqlite' (best, when app is closed),
                        'raw' (fallback stream scan), 'auto' (default)

```

Environment variables supported:
- `OP_SECRET_KEY`
- `OP_MASTER_PASSWORD`
- `OP_EMAIL`

---

## 🔀 Vault Migration & 3-Way Merge (`migrate-op`)

To migrate or merge vaults between accounts (e.g. merging Vault A from Account `Our` with Vault B from Account `Azote the Tester`):

```bash
uv run migrate-op
```

### Features:
- **Interactive Account & Vault Selection**: Decrypts Account A and lets you pick Vault A; decrypts Account B (or loads from an existing `.1pux` / `.json` file) and lets you pick Vault B.
- **Item ID Matching**: Pairs items automatically using their unique `id`.
- **Intelligent 3-Way / 2-Way Merge**:
  - Automatically merges unique items from both vaults.
  - For common items, compares `updatedAt` timestamps (Last Write Wins) and preserves non-conflicting custom fields.
  - Supports `--base <ancestor.json>` for true 3-way merge.
- **Dual Export**: Generates both an importable `.1pux` package and a clean, merged `.json` file with merge statistics and conflict logs.

```bash
# Example non-interactive / automated invocation:
uv run migrate-op -A 1 -B 2 -o merged_vault.1pux -j merged_vault.json
```

---

## 🔐 How It Works

1. **Two-Secret Key Derivation (2SKD)**:
   Combines your Master Password and Secret Key (`A3-...`) using HKDF + PBKDF2-HMAC-SHA256 and bitwise XOR to derive the Master Unlock Key (MUK).
2. **Master Key (MK) & RSA Private Key**:
   Decrypts the 256-bit symmetric Master Key using AES-256-GCM, which in turn decrypts your account's RSA private key.
3. **Vault Keys**:
   Decrypts vault symmetric keys using RSA-OAEP.
4. **Item Association (Overview + Details)**:
   Decrypts item `overview` (title, URL, username) and item `details` (passwords, custom fields, notes) in tandem from the SQLite table rows.
5. **1PUX Packaging**:
   Formats the decrypted records into the standard 1PUX schema (`export.attributes`, `export.data`, `files/`) and generates a ready-to-import `.1pux` zip archive.

---

## 📦 What about Docker?
The previous Dockerfile was used solely to run Python 2 and install an obsolete dependency (`pyjwkest`).
This project has been completely refactored for **Python 3** and modern standards:
- Deprecated `pyjwkest` replaced with native standard library JWK decoding.
- Cross-platform support across Windows, macOS, and Linux.
- Instant venv resolution with `uv`.
