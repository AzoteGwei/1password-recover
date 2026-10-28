import argparse
import copy
import getpass
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from recover_op.cli import ask_email, ask_master_password, ask_secret_key
from recover_op.crypto import (
    b64url_decode,
    b64url_encode,
    compute_2skd,
    dec_aes_gcm,
    dec_rsa_oaep,
    decode_payload,
    enc_aes_gcm,
    parse_rsa_jwk,
)
from recover_op.extractor import RecoveryExtractor, _safe_json_parse
from recover_op.merger import sanitize_item_for_migration
from recover_op.pux import load_items_from_file


def _backup_database(db_path: Path) -> Path:
    """Create a timestamped backup of the database before in-place modification."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    backup_path = db_path.with_name(f"{db_path.name}.backup_{ts}")
    shutil.copy2(db_path, backup_path)
    return backup_path


def _resolve_vault_key_op8(
    db_path: Path,
    target_account_uuid: str,
    target_vault_uuid: str,
    secret_key: str = "",
    master_password: str = "",
    email: str = "",
    raw_vault_key_b64: str = "",
) -> Tuple[bytes, str]:
    """
    Derive or decrypt the Vault Key for the given target account and vault in 1Password 8.
    Returns (vault_key_bytes, vault_key_kid).
    """
    # If user provided a raw vault key
    if raw_vault_key_b64:
        vk_bytes = b64url_decode(raw_vault_key_b64.strip())
        return vk_bytes, target_vault_uuid

    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Read target vault's enc_vault_key
    cursor.execute(
        "SELECT data FROM vaults WHERE account_uuid = ? AND vault_uuid = ?",
        (target_account_uuid, target_vault_uuid),
    )
    v_row = cursor.fetchone()
    if not v_row:
        conn.close()
        raise ValueError(f"Vault '{target_vault_uuid}' not found for account '{target_account_uuid}'.")

    v_data = _safe_json_parse(v_row["data"]) or {}
    enc_vk = v_data.get("enc_vault_key") or v_data.get("encVaultKey")
    if not enc_vk or "data" not in enc_vk:
        conn.close()
        raise ValueError("enc_vault_key missing from target vault record.")

    # Check kid from enc_attrs if available
    enc_attrs = v_data.get("enc_attrs") or v_data.get("encAttrs")
    vk_kid = enc_attrs.get("kid", target_vault_uuid) if enc_attrs else target_vault_uuid

    # 2. Decrypt MK from objects_associated
    cursor.execute(
        "SELECT data FROM objects_associated WHERE account_uuid = ? AND (type = 36 OR data LIKE '%encSymKey%')",
        (target_account_uuid,),
    )
    keyset_rows = cursor.fetchall()
    if not keyset_rows:
        conn.close()
        raise ValueError(f"No keysets found for account '{target_account_uuid}'.")

    muk = None
    mk_dict = None
    mk_key_bytes = None
    rsa_key = None

    for r in keyset_rows:
        obj = _safe_json_parse(r[0])
        if not obj:
            continue
        enc_sym = obj.get("encSymKey") or obj.get("enc_sym_key")
        enc_pri = obj.get("encPriKey") or obj.get("enc_pri_key")

        if enc_sym and "p2s" in enc_sym and "data" in enc_sym:
            p2s = decode_payload(enc_sym["p2s"])
            p2c = int(enc_sym["p2c"])
            alg = enc_sym.get("alg") or "PBES2g-HS256"
            iv = decode_payload(enc_sym["iv"])
            ct = decode_payload(enc_sym["data"])

            try:
                muk = compute_2skd(secret_key, master_password, email, p2s, p2c, alg)
                dec_mk = dec_aes_gcm(ct, muk, iv)
                mk_dict = json.loads(dec_mk.decode("utf-8"))
                mk_key_bytes = b64url_decode(mk_dict["k"])

                if enc_pri and "data" in enc_pri and "iv" in enc_pri:
                    p_iv = decode_payload(enc_pri["iv"])
                    p_ct = decode_payload(enc_pri["data"])
                    dec_rsa = dec_aes_gcm(p_ct, mk_key_bytes, p_iv)
                    rsa_key = parse_rsa_jwk(dec_rsa)
                break
            except Exception:
                continue

    if not mk_dict or not mk_key_bytes or not rsa_key:
        conn.close()
        raise ValueError(
            "Failed to decrypt Master Key or RSA private key for target account. Please verify credentials."
        )

    # 3. Decrypt vault key via RSA-OAEP
    ct = decode_payload(enc_vk["data"])
    dec_vk_json = dec_rsa_oaep(rsa_key, ct)
    vk_obj = json.loads(dec_vk_json.decode("utf-8"))
    vk_bytes = b64url_decode(vk_obj["k"])
    vk_kid = vk_obj.get("kid", vk_kid)

    conn.close()
    return vk_bytes, vk_kid


def main():
    parser = argparse.ArgumentParser(
        description="1Password In-Place Vault Injector & Replace Tool (replace-op)"
    )
    parser.add_argument(
        "--db",
        "-d",
        default="1password.sqlite",
        help="Path to 1password.sqlite database file (default: 1password.sqlite)",
    )
    parser.add_argument(
        "--source",
        "-s",
        default="",
        help="Path to source .1pux or .json file to inject (contains items to be imported)",
    )
    parser.add_argument(
        "--target-account",
        "-A",
        default="",
        help="Target account index (e.g. 1, 2), UUID, or email in 1password.sqlite",
    )
    parser.add_argument(
        "--target-vault",
        "-V",
        default="",
        help="Target vault UUID or index within target account",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate encryption and injection without modifying the database",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip automatic database backup before modification (not recommended)",
    )

    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    if not db_path.exists():
        print(f"[-] Error: Database file not found at '{db_path}'.")
        sys.exit(1)

    print(f"[*] Found 1Password database: {db_path} ({db_path.stat().st_size / 1024 / 1024:.2f} MB)")
    print("-" * 70)

    # 1. Load Source Items
    source_file = args.source
    if not source_file:
        source_file = input("Enter path to source file (.1pux or .json): ").strip()

    source_path = Path(source_file).resolve()
    if not source_path.exists():
        print(f"[-] Error: Source file not found at '{source_path}'.")
        sys.exit(1)

    print(f"[*] Loading and sanitizing items from '{source_path.name}'...")
    raw_items = load_items_from_file(source_path)
    print(f"[+] Loaded {len(raw_items)} items from source.")

    # Sanitize items (strip file/server references, retain passkeys!)
    sanitized_items = [sanitize_item_for_migration(item) for item in raw_items]
    passkey_count = sum(
        1
        for it in sanitized_items
        if str(it.get("categoryUuid")) == "116"
        or any(
            str(f.get("type", "")).lower() == "passkey"
            or "passkey" in str(f.get("designation", "")).lower()
            for f in it.get("details", {}).get("fields", [])
            if isinstance(f, dict)
        )
    )
    print(f"[+] Sanitized {len(sanitized_items)} items (files stripped, {passkey_count} passkey items preserved).")

    # 2. Select Target Account
    extractor = RecoveryExtractor(str(db_path))
    accounts = extractor.inspect_accounts()
    if not accounts:
        print("[-] Error: No accounts found in target database.")
        sys.exit(1)

    target_account = None
    if args.target_account:
        for idx, acc in enumerate(accounts, 1):
            if args.target_account == str(idx) or args.target_account.lower() in [
                acc["id"].lower(),
                acc["uuid"].lower(),
                acc["email"].lower(),
                acc["name"].lower(),
            ]:
                target_account = acc
                break

    if not target_account:
        print(f"\n[*] Available Accounts in database:")
        for idx, acc in enumerate(accounts, 1):
            print(f"    [{idx}] {acc['name']} ({acc['email']} | UUID: {acc['uuid']})")
        while True:
            choice = input(f"👉 Select Target Account [1-{len(accounts)}] (default: 1): ").strip() or "1"
            try:
                c_idx = int(choice)
                if 1 <= c_idx <= len(accounts):
                    target_account = accounts[c_idx - 1]
                    break
            except ValueError:
                pass
            print(f"   Please enter a number between 1 and {len(accounts)}.")

    target_acc_uuid = target_account["uuid"]
    target_acc_name = target_account["name"]
    target_acc_email = target_account["email"]
    print(f"\n[+] Target Account: {target_acc_name} ({target_acc_email or target_acc_uuid})")

    # 3. Select Target Vault
    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn_ro = sqlite3.connect(uri, uri=True)
    conn_ro.row_factory = sqlite3.Row
    cur_ro = conn_ro.cursor()

    cur_ro.execute("SELECT vault_uuid, data FROM vaults WHERE account_uuid = ?", (target_acc_uuid,))
    vault_rows = cur_ro.fetchall()
    conn_ro.close()

    if not vault_rows:
        print(f"[-] Error: No vaults found for target account '{target_acc_uuid}'.")
        sys.exit(1)

    target_vault_uuid = None
    if args.target_vault:
        for idx, vr in enumerate(vault_rows, 1):
            if args.target_vault == str(idx) or args.target_vault == vr["vault_uuid"]:
                target_vault_uuid = vr["vault_uuid"]
                break

    if not target_vault_uuid:
        print(f"\n[*] Available Vaults in Target Account:")
        for idx, vr in enumerate(vault_rows, 1):
            v_dict = _safe_json_parse(vr["data"]) or {}
            enc_attrs = v_dict.get("enc_attrs") or v_dict.get("encAttrs") or {}
            print(f"    [{idx}] Vault UUID: {vr['vault_uuid']}")
        while True:
            choice = input(f"👉 Select Target Vault [1-{len(vault_rows)}] (default: 1): ").strip() or "1"
            try:
                c_idx = int(choice)
                if 1 <= c_idx <= len(vault_rows):
                    target_vault_uuid = vault_rows[c_idx - 1]["vault_uuid"]
                    break
            except ValueError:
                pass
            print(f"   Please enter a number between 1 and {len(vault_rows)}.")

    print(f"\n[+] Target Vault: {target_vault_uuid}")

    # 4. Resolve Target Vault Key
    print("\n----------------------------------------------------------------------")
    print(f"[*] Authenticating Target Account '{target_acc_name}' to derive Vault Key...")
    secret_key = ask_secret_key()
    master_password = ask_master_password()
    email = ask_email(default_hint=target_acc_email)

    try:
        vk_bytes, vk_kid = _resolve_vault_key_op8(
            db_path=db_path,
            target_account_uuid=target_acc_uuid,
            target_vault_uuid=target_vault_uuid,
            secret_key=secret_key,
            master_password=master_password,
            email=email,
        )
        print(f"[+] Successfully derived Target Vault Key (kid: {vk_kid})!")
    except Exception as e:
        print(f"[-] Failed to derive target vault key: {e}")
        sys.exit(1)

    # 5. Backup before modification
    if not args.dry_run and not args.no_backup:
        backup_file = _backup_database(db_path)
        print(f"\n[+] Created automatic backup of database: {backup_file}")

    # 6. Encrypt and In-Place Write
    now_ts = int(time.time())
    print(f"\n[*] Encrypting {len(sanitized_items)} items with Target Vault Key...")

    encrypted_records = []
    for it in sanitized_items:
        i_uuid = it.get("id") or it.get("uuid")
        if not i_uuid:
            continue

        ov = it.get("overview", {})
        det = it.get("details", {})
        cat = it.get("categoryUuid") or it.get("category_uuid") or "001"
        item_ts = it.get("updatedAt") or now_ts

        # Encrypt overview
        ov_bytes = json.dumps(ov, ensure_ascii=False).encode("utf-8")
        enc_ov, ov_iv = enc_aes_gcm(ov_bytes, vk_bytes)

        # Encrypt details
        det_bytes = json.dumps(det, ensure_ascii=False).encode("utf-8")
        enc_det, det_iv = enc_aes_gcm(det_bytes, vk_bytes)

        item_envelope = {
            "category_uuid": str(cat),
            "changer_uuid": target_acc_uuid,
            "created_at": it.get("createdAt") or now_ts,
            "details": {
                "cty": "b5+jwk+json",
                "kid": vk_kid,
                "enc": "A256GCM",
                "iv": b64url_encode(det_iv),
                "data": b64url_encode(enc_det),
            },
            "is_favorite": it.get("is_favorite", False),
            "overview": {
                "cty": "b5+jwk+json",
                "kid": vk_kid,
                "enc": "A256GCM",
                "iv": b64url_encode(ov_iv),
                "data": b64url_encode(enc_ov),
            },
            "state": "N",
            "updated_at": item_ts,
            "validated": True,
        }

        blob_bytes = json.dumps(item_envelope, ensure_ascii=False).encode("utf-8")
        encrypted_records.append((
            target_acc_uuid,
            target_vault_uuid,
            i_uuid,
            1,  # local_edit_count (signals client to sync with cloud)
            0,  # rejection_reason
            1,  # version
            blob_bytes,
        ))

    if args.dry_run:
        print(f"\n[DRY RUN] Would write {len(encrypted_records)} items to 'items' table.")
        print("[DRY RUN] Database was NOT modified.")
        sys.exit(0)

    # In-place database write in an atomic transaction
    print(f"[*] In-place writing {len(encrypted_records)} items into '{db_path.name}'...")
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        cur.executemany(
            """
            INSERT OR REPLACE INTO items (
                account_uuid,
                vault_uuid,
                item_uuid,
                local_edit_count,
                rejection_reason,
                version,
                data
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            encrypted_records,
        )
        conn.commit()
        print(f"✅ Successfully injected {len(encrypted_records)} items into Target Vault '{target_vault_uuid}'!")
    except Exception as e:
        conn.rollback()
        print(f"[-] Database write failed: {e}")
        sys.exit(1)
    finally:
        conn.close()

    print("\n----------------------------------------------------------------------")
    print("🎉 In-Place Import (replace-op) Complete!")
    print(f"• Target Account: {target_acc_name} ({target_acc_email})")
    print(f"• Target Vault:   {target_vault_uuid}")
    print(f"• Injected Items: {len(encrypted_records)} (including {passkey_count} Passkeys)")
    print("\n⚠️ IMPORTANT POST-IMPORT NOTES:")
    print("1. If 1Password was closed, you can now launch 1Password.")
    print("2. 1Password will detect local_edit_count = 1 and sync the newly injected items (including passkeys) to the 1Password cloud.")
    print(f"3. If anything looks unexpected, you can restore your backup: '{backup_file.name}'")


if __name__ == "__main__":
    main()
