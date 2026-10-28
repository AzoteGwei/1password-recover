import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from recover_op.cli import ask_email, ask_master_password, ask_secret_key
from recover_op.extractor import RecoveryExtractor
from recover_op.merger import merge_vault_items
from recover_op.pux import build_1pux_package, load_items_from_file


def _select_vault(vaults: List[Dict[str, Any]], label: str = "Vault") -> Dict[str, Any]:
    """Interactively select a vault from a list of decrypted vaults."""
    if not vaults:
        raise ValueError(f"No vaults found for {label}.")

    if len(vaults) == 1:
        v = vaults[0]
        v_name = v.get("attrs", {}).get("name", "Unnamed Vault")
        cnt = len(v.get("items", []))
        print(f"[+] Only 1 vault found in {label}: '{v_name}' ({cnt} items) -> automatically selected.")
        return v

    print(f"\n[*] Available vaults in {label}:")
    for idx, v in enumerate(vaults, 1):
        v_name = v.get("attrs", {}).get("name", f"Vault {idx}")
        cnt = len(v.get("items", []))
        print(f"    [{idx}] {v_name} ({cnt} items)")

    while True:
        choice = input(f"👉 Select {label} [1-{len(vaults)}] (default: 1): ").strip() or "1"
        try:
            choice_idx = int(choice)
            if 1 <= choice_idx <= len(vaults):
                return vaults[choice_idx - 1]
        except ValueError:
            pass
        print(f"   Please enter a number between 1 and {len(vaults)}.")


def _decrypt_account_vault(
    extractor: RecoveryExtractor,
    account: Dict[str, Any],
    account_label: str = "Account",
    force_mode: str = "auto",
) -> Tuple[str, List[Dict[str, Any]]]:
    """Prompt credentials, decrypt vaults for an account, and return the chosen vault's items."""
    acc_name = account.get("name", "Account")
    acc_email = account.get("email", "")
    acc_uuid = account.get("uuid", "")

    print(f"\n======================================================================")
    print(f"[*] Decrypting {account_label}: {acc_name} ({acc_email or acc_uuid})")
    print(f"======================================================================")

    secret_key = ask_secret_key()
    master_password = ask_master_password()
    email = ask_email(default_hint=acc_email)

    print(f"\n[*] Decrypting vaults for {acc_name}...")
    vaults = extractor.run(
        secret_key=secret_key,
        master_password=master_password,
        email=email,
        force_mode=force_mode,
        account_id=account.get("id"),
        account_uuid=account.get("uuid"),
    )

    chosen_vault = _select_vault(vaults, label=f"Account {acc_name}")
    v_name = chosen_vault.get("attrs", {}).get("name", "Vault")
    items = chosen_vault.get("items", [])
    print(f"[+] Selected Vault '{v_name}' with {len(items)} items from {acc_name}.")
    return v_name, items


def main():
    parser = argparse.ArgumentParser(
        description="1Password Raw Vault Migration & 3-Way JSON Merger (migrate-op)"
    )
    parser.add_argument(
        "--db",
        "-d",
        default="1password.sqlite",
        help="Path to 1password.sqlite database file (default: 1password.sqlite)",
    )
    parser.add_argument(
        "--account-a",
        "-A",
        default="",
        help="Source Account A identifier (name, index e.g. 1, email, or UUID)",
    )
    parser.add_argument(
        "--account-b",
        "-B",
        default="",
        help="Target Account B identifier (name, index e.g. 2, email, or UUID)",
    )
    parser.add_argument(
        "--file-b",
        default="",
        help="Optional path to external .1pux or .json for Account B (if B is passkey or already decrypted)",
    )
    parser.add_argument(
        "--base",
        "-b",
        default="",
        help="Optional path to Base ancestor .1pux or .json file for true 3-way merge",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="",
        help="Output path for merged .1pux file (default: merged_vault_<timestamp>.1pux)",
    )
    parser.add_argument(
        "--json-output",
        "-j",
        default="",
        help="Output path for merged .json file (default: merged_vault_<timestamp>.json)",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "sqlite", "raw"],
        default="auto",
        help="Extraction strategy: 'sqlite' (best), 'raw', 'auto' (default)",
    )

    args = parser.parse_args()

    # Locate database
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
        sys.exit(1)

    print(f"[*] Found 1Password database: {db_path.resolve()}")
    extractor = RecoveryExtractor(str(db_path))
    accounts = extractor.inspect_accounts()

    if not accounts:
        print("[-] Error: No accounts discovered in database.")
        sys.exit(1)

    print(f"\n[*] Discovered {len(accounts)} accounts in database:")
    for idx, acc in enumerate(accounts, 1):
        info_parts = []
        if acc["email"]:
            info_parts.append(acc["email"])
        if acc.get("item_count"):
            info_parts.append(f"{acc['item_count']} items, {acc.get('vault_count', 0)} vaults")
        if acc["uuid"]:
            info_parts.append(f"UUID: {acc['uuid']}")
        info_str = " | ".join(info_parts) if info_parts else f"ID: {acc['id']}"
        print(f"    [{idx}] {acc['name']} ({info_str})")

    # -------------------------------------------------------------------------
    # 1. Select Account A
    # -------------------------------------------------------------------------
    acc_a = None
    if args.account_a:
        for idx, a in enumerate(accounts, 1):
            if args.account_a == str(idx) or args.account_a.lower() in [
                a["id"].lower(),
                a["uuid"].lower(),
                a["email"].lower(),
                a["name"].lower(),
            ]:
                acc_a = a
                break

    if not acc_a:
        while True:
            choice = input(f"\n👉 Select Source Account A [1-{len(accounts)}] (default: 1): ").strip() or "1"
            try:
                c_idx = int(choice)
                if 1 <= c_idx <= len(accounts):
                    acc_a = accounts[c_idx - 1]
                    break
            except ValueError:
                pass
            print(f"   Please enter a number between 1 and {len(accounts)}.")

    vault_a_name, items_a = _decrypt_account_vault(
        extractor, acc_a, account_label="Source Account A", force_mode=args.mode
    )

    # -------------------------------------------------------------------------
    # 2. Select Account B / Vault B
    # -------------------------------------------------------------------------
    items_b = []
    vault_b_name = "Target Vault"

    if args.file_b:
        print(f"\n[*] Loading Vault B from external file: {args.file_b}")
        items_b = load_items_from_file(args.file_b)
        vault_b_name = Path(args.file_b).stem
        print(f"[+] Loaded {len(items_b)} items for Vault B from '{args.file_b}'.")
    else:
        # Ask user whether to decrypt from DB or load external file
        print(f"\n----------------------------------------------------------------------")
        print("[*] Destination Vault B Source:")
        print("    [1] Decrypt an account from this SQLite database")
        print("    [2] Load from an already-decrypted .1pux or .json file")
        b_source_choice = input("👉 Select source for Vault B [1-2] (default: 1): ").strip() or "1"

        if b_source_choice == "2":
            file_b_path = input("Enter path to Vault B file (.1pux or .json): ").strip()
            items_b = load_items_from_file(file_b_path)
            vault_b_name = Path(file_b_path).stem
            print(f"[+] Loaded {len(items_b)} items for Vault B from '{file_b_path}'.")
        else:
            # Select account B from SQLite
            acc_b = None
            default_b_idx = 2 if len(accounts) >= 2 else 1
            if args.account_b:
                for idx, a in enumerate(accounts, 1):
                    if args.account_b == str(idx) or args.account_b.lower() in [
                        a["id"].lower(),
                        a["uuid"].lower(),
                        a["email"].lower(),
                        a["name"].lower(),
                    ]:
                        acc_b = a
                        break

            if not acc_b:
                while True:
                    choice = (
                        input(
                            f"\n👉 Select Target Account B [1-{len(accounts)}] (default: {default_b_idx}): "
                        ).strip()
                        or str(default_b_idx)
                    )
                    try:
                        c_idx = int(choice)
                        if 1 <= c_idx <= len(accounts):
                            acc_b = accounts[c_idx - 1]
                            break
                    except ValueError:
                        pass
                    print(f"   Please enter a number between 1 and {len(accounts)}.")

            vault_b_name, items_b = _decrypt_account_vault(
                extractor, acc_b, account_label="Target Account B", force_mode=args.mode
            )

    # -------------------------------------------------------------------------
    # 3. Optional Base Ancestor
    # -------------------------------------------------------------------------
    items_base = None
    if args.base:
        print(f"\n[*] Loading Base ancestor from: {args.base}")
        items_base = load_items_from_file(args.base)
        print(f"[+] Loaded {len(items_base)} base items for 3-way merge.")

    # -------------------------------------------------------------------------
    # 4. Execute Merge
    # -------------------------------------------------------------------------
    merge_type = "3-Way Merge (with Base)" if items_base else "2-Way Intelligent Merge (LWW & Field Combination)"
    print(f"\n======================================================================")
    print(f"[*] Executing {merge_type} on item IDs...")
    print(f"    • Vault A ('{vault_a_name}'): {len(items_a)} items")
    print(f"    • Vault B ('{vault_b_name}'): {len(items_b)} items")
    if items_base:
        print(f"    • Base Ancestor: {len(items_base)} items")
    print(f"======================================================================")

    merged_items, stats = merge_vault_items(items_a, items_b, items_base)

    print("\n[+] Merge Statistics:")
    print(f"    • Total items in merged vault: {stats['total_merged']}")
    print(f"    • Items exclusive to Vault A:   {stats['only_in_a']}")
    print(f"    • Items exclusive to Vault B:   {stats['only_in_b']}")
    print(f"    • Items identical in both:      {stats['in_both_identical']}")
    print(f"    • Items merged & updated:       {stats['in_both_merged']}")

    if stats["conflict_logs"]:
        print(f"\n[*] Resolved Field Conflicts ({len(stats['conflict_logs'])} items):")
        for log in stats["conflict_logs"][:15]:
            print(f"    - {log}")
        if len(stats["conflict_logs"]) > 15:
            print(f"    ... and {len(stats['conflict_logs']) - 15} more.")

    # -------------------------------------------------------------------------
    # 5. Export Output
    # -------------------------------------------------------------------------
    timestamp = int(time.time())
    merged_vault_name = f"Merged_{vault_a_name}_{vault_b_name}"
    merged_vault = {
        "attrs": {
            "uuid": f"merged-vault-{timestamp}",
            "name": merged_vault_name,
            "desc": f"Merged from '{vault_a_name}' and '{vault_b_name}'",
        },
        "items": merged_items,
    }

    # 1. 1PUX export
    out_1pux_name = args.output or f"merged_{vault_a_name}_{timestamp}.1pux"
    out_1pux_path = build_1pux_package(
        output_path=out_1pux_name,
        vaults=[merged_vault],
        email=acc_a.get("email") or "merged@example.com",
        account_name=acc_a.get("name") or "Merged Account",
    )
    print(f"\n[+] Exported Merged 1PUX package: {out_1pux_path.resolve()}")

    # 2. JSON export
    out_json_name = args.json_output or f"merged_{vault_a_name}_{timestamp}.json"
    out_json_path = Path(out_json_name).resolve()
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "vault": merged_vault_name,
                "mergedAt": timestamp,
                "stats": stats,
                "items": merged_items,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"[+] Exported Merged JSON file:    {out_json_path}")

    print("\n🎉 Migration & Merge successful!")
    print("👉 You can now import the .1pux file directly into 1Password 8, Bitwarden, or KeePassXC.")


if __name__ == "__main__":
    main()
