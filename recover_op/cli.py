import argparse
import getpass
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from recover_op.extractor import RecoveryExtractor
from recover_op.pux import build_1pux_package


def ask_secret_key(given_val: str = "") -> str:
    if given_val:
        return given_val.strip()
    env_val = os.getenv("OP_SECRET_KEY")
    if env_val:
        return env_val.strip()
    while True:
        val = getpass.getpass("Enter Secret Key (e.g. A3-xxxxxx-xxxxxx-...): ").strip()
        if val:
            return val
        print("   Secret Key cannot be empty.")


def ask_master_password(given_val: str = "") -> str:
    if given_val:
        return given_val
    env_val = os.getenv("OP_MASTER_PASSWORD")
    if env_val:
        return env_val
    while True:
        val = getpass.getpass("Enter Master Password: ")
        if val:
            return val
        print("   Master Password cannot be empty.")


def ask_email(given_val: str = "", default_hint: str = "") -> str:
    if given_val:
        return given_val.strip()
    env_val = os.getenv("OP_EMAIL")
    if env_val:
        return env_val.strip()
    prompt_str = f"Enter Account Email (press Enter for '{default_hint}'): " if default_hint else "Enter Account Email: "
    while True:
        val = input(prompt_str).strip()
        if val:
            return val
        if default_hint:
            return default_hint
        print("   Email cannot be empty.")


def main():
    parser = argparse.ArgumentParser(
        description="1Password SQLite Database Decryptor & 1PUX Exporter (Python 3 + UV)"
    )
    parser.add_argument(
        "--db",
        "-d",
        default="1password.sqlite",
        help="Path to 1password.sqlite database file (default: 1password.sqlite)",
    )
    parser.add_argument(
        "--account",
        "-a",
        default="",
        help="Account to decrypt by index (e.g. 1, 2), UUID, or email (useful when multiple accounts exist)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="",
        help="Path for output .1pux file (default: recovered_<timestamp>.1pux)",
    )
    parser.add_argument(
        "--email",
        "-e",
        default="",
        help="1Password account email address",
    )
    parser.add_argument(
        "--secret-key",
        "-s",
        default="",
        help="1Password account Secret Key (A3-...)",
    )
    parser.add_argument(
        "--password",
        "-p",
        default="",
        help="1Password account Master Password",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "sqlite", "raw"],
        default="auto",
        help="Extraction strategy: 'sqlite' (best, when app is closed), 'raw' (fallback stream scan), 'auto' (default)",
    )

    args = parser.parse_args()

    # Locate database file
    db_candidates = [
        Path(args.db),
        Path("recover_op") / args.db,
        Path("1password.sqlite"),
        Path("recover_op/1password.sqlite"),
    ]
    db_path = None
    for cand in db_candidates:
        if cand.exists() and cand.is_file():
            db_path = cand
            break

    if not db_path:
        print(f"[-] Error: Database file not found at '{args.db}'.")
        print("    Please copy your '1password.sqlite' to the current directory or specify with --db.")
        sys.exit(1)

    print(f"[*] Found 1Password database: {db_path.resolve()} ({db_path.stat().st_size / 1024 / 1024:.2f} MB)")
    print("-" * 70)

    extractor = RecoveryExtractor(str(db_path))

    # Inspect accounts in database
    accounts = extractor.inspect_accounts()
    selected_account = None

    if accounts:
        if len(accounts) > 1:
            print(f"[*] Discovered {len(accounts)} accounts in database:")
            for idx, acc in enumerate(accounts, 1):
                info_parts = []
                if acc["email"]:
                    info_parts.append(acc["email"])
                if acc.get("item_count"):
                    info_parts.append(f"{acc['item_count']} items, {acc.get('vault_count', 0)} vaults")
                if acc["server"]:
                    info_parts.append(acc["server"])
                if acc["uuid"]:
                    info_parts.append(f"UUID: {acc['uuid']}")
                info_str = " | ".join(info_parts) if info_parts else f"ID: {acc['id']}"
                print(f"    [{idx}] {acc['name']} ({info_str})")

            # Check if user specified --account flag
            if args.account:
                for idx, acc in enumerate(accounts, 1):
                    if args.account == str(idx) or args.account.lower() in [
                        acc["id"].lower(),
                        acc["uuid"].lower(),
                        acc["email"].lower(),
                    ]:
                        selected_account = acc
                        break
                if not selected_account:
                    print(f"[-] Account matching '{args.account}' not found.")

            if not selected_account:
                while True:
                    choice = (
                        input(f"\nSelect account to decrypt [1-{len(accounts)}] (default: 1): ").strip()
                        or "1"
                    )
                    try:
                        choice_idx = int(choice)
                        if 1 <= choice_idx <= len(accounts):
                            selected_account = accounts[choice_idx - 1]
                            break
                    except ValueError:
                        pass
                    print(f"   Please enter a number between 1 and {len(accounts)}.")
        else:
            selected_account = accounts[0]

    account_id = None
    account_uuid = None
    default_email_hint = ""

    if selected_account:
        account_id = selected_account.get("id")
        account_uuid = selected_account.get("uuid")
        default_email_hint = selected_account.get("email", "")
        print(f"\n[+] Active account: {selected_account['name']} ({default_email_hint or account_uuid})")

    # Secure interactive prompts
    secret_key = ask_secret_key(args.secret_key)
    master_password = ask_master_password(args.password)
    email = ask_email(args.email, default_hint=default_email_hint)

    print("\n[*] Deriving keys and decrypting vaults...")
    try:
        vaults = extractor.run(
            secret_key,
            master_password,
            email,
            force_mode=args.mode,
            account_id=account_id,
            account_uuid=account_uuid,
        )
    except Exception as e:
        print(f"\n[-] Decryption failed: {e}")
        print("    Tips:")
        print("    1. Verify your Secret Key, Master Password, and Email.")
        print("    2. If multiple accounts exist, verify you selected the password-protected account.")
        print("    3. Make sure 1Password was completely quit before copying 1password.sqlite.")
        sys.exit(1)

    # Calculate statistics
    total_items = sum(len(v.get("items", [])) for v in vaults)
    print(f"\n[+] Successfully decrypted {len(vaults)} vault(s) and {total_items} item(s)!")

    for i, v in enumerate(vaults, 1):
        v_name = v.get("attrs", {}).get("name", f"Vault {i}")
        items_count = len(v.get("items", []))
        print(f"    - Vault {i}: '{v_name}' -> {items_count} items")

    # Build 1PUX export
    timestamp = int(time.time())
    account_name_clean = ""
    if selected_account and selected_account.get("name"):
        account_name_clean = "".join(c for c in selected_account["name"] if c.isalnum() or c in "-_")
    
    out_default_prefix = f"recovered_{account_name_clean}_{timestamp}" if account_name_clean else f"recovered_{timestamp}"
    out_name = args.output or f"{out_default_prefix}.1pux"

    out_file = build_1pux_package(
        output_path=out_name,
        vaults=vaults,
        email=email,
        account_uuid=account_uuid or "",
        account_name=selected_account.get("name", "") if selected_account else "",
    )

    print(f"\n[+] Exported 1PUX package: {out_file.resolve()}")
    print("[*] You can now directly import this .1pux file into:")
    print("    - 1Password 8 (File -> Import -> 1Password Unencrypted Export)")
    print("    - KeePassXC (Database -> Import -> 1Password .1pux)")
    print("    - Bitwarden (Tools -> Import Data -> 1Password (1pux))")


if __name__ == "__main__":
    main()
