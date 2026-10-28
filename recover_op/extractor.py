import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from recover_op.crypto import (
    b64url_decode,
    compute_2skd,
    dec_aes_gcm,
    dec_rsa_oaep,
    decode_payload,
    parse_rsa_jwk,
)


def _safe_json_parse(val: Any) -> Optional[Dict[str, Any]]:
    """Safely parse value into a dict if possible."""
    if isinstance(val, dict):
        return val
    if isinstance(val, (bytes, bytearray)):
        val = val.decode("utf-8", errors="ignore")
    if isinstance(val, str):
        val = val.strip()
        if (val.startswith("{") and val.endswith("}")) or (val.startswith("[") and val.endswith("]")):
            try:
                return json.loads(val)
            except Exception:
                return None
    return None


class RecoveryExtractor:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path).resolve()
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database file not found: {self.db_path}")

    def inspect_accounts(self) -> List[Dict[str, Any]]:
        """
        Inspect the database and return a list of discovered accounts.
        Supports both 1Password 8 (JSON BLOBs in accounts table) and 1Password 7.
        """
        uri = f"file:{self.db_path.as_posix()}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
        except Exception:
            return []

        accounts = []
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"].lower(): row["name"] for row in cursor.fetchall()}

            accounts_table = tables.get("accounts") or tables.get("account")
            if accounts_table:
                cursor.execute(f"PRAGMA table_info({accounts_table})")
                cols = {r["name"].lower(): r["name"] for r in cursor.fetchall()}

                cursor.execute(f"SELECT * FROM {accounts_table}")
                rows = cursor.fetchall()
                for r in rows:
                    d = dict(r)
                    acc_uuid = d.get("account_uuid") or d.get("uuid") or str(d.get("id"))

                    # 1Password 8: attributes inside JSON blob 'data'
                    blob_data = _safe_json_parse(d.get("data"))
                    if blob_data:
                        email = blob_data.get("user_email") or blob_data.get("email") or ""
                        name = (
                            blob_data.get("team_name")
                            or blob_data.get("user_name")
                            or f"Account {acc_uuid[:8]}"
                        )
                        server = blob_data.get("sign_in_url") or blob_data.get("server") or ""
                        sign_in_provider = blob_data.get("sign_in_provider") or ""

                        # Count vaults & items if tables exist
                        vault_count = 0
                        item_count = 0
                        if "vaults" in tables:
                            cursor.execute("SELECT count(*) FROM vaults WHERE account_uuid = ?", (acc_uuid,))
                            vault_count = cursor.fetchone()[0]
                        if "items" in tables:
                            cursor.execute("SELECT count(*) FROM items WHERE account_uuid = ?", (acc_uuid,))
                            item_count = cursor.fetchone()[0]

                        accounts.append({
                            "id": acc_uuid,
                            "uuid": acc_uuid,
                            "name": name,
                            "email": email,
                            "server": server,
                            "sign_in_provider": sign_in_provider,
                            "vault_count": vault_count,
                            "item_count": item_count,
                            "raw": blob_data,
                        })
                        continue

                    # 1Password 7: column-based attributes
                    acc_id = d.get("id") or acc_uuid
                    email = d.get("user_email") or d.get("email") or ""
                    team_name = d.get("team_name")
                    first = d.get("user_first_name") or ""
                    last = d.get("user_last_name") or ""
                    user_name = f"{first} {last}".strip()
                    name = team_name or user_name or d.get("name") or f"Account {acc_id}"
                    server = d.get("server") or ""

                    accounts.append({
                        "id": str(acc_id),
                        "uuid": str(acc_uuid),
                        "name": name,
                        "email": email,
                        "server": server,
                        "vault_count": 0,
                        "item_count": 0,
                        "raw": d,
                    })

            # If no accounts found in accounts table, check keysets
            if not accounts:
                keysets_table = tables.get("keysets") or tables.get("keyset")
                if keysets_table:
                    cursor.execute(f"PRAGMA table_info({keysets_table})")
                    k_cols = {r["name"].lower(): r["name"] for r in cursor.fetchall()}
                    acc_col = k_cols.get("account_id") or k_cols.get("account_uuid")
                    if acc_col:
                        cursor.execute(f"SELECT DISTINCT {acc_col} FROM {keysets_table}")
                        for r in cursor.fetchall():
                            val = r[0]
                            if val is not None:
                                accounts.append({
                                    "id": str(val),
                                    "uuid": str(val),
                                    "name": f"Account {val}",
                                    "email": "",
                                    "server": "",
                                    "vault_count": 0,
                                    "item_count": 0,
                                    "raw": {acc_col: val},
                                })
        finally:
            conn.close()

        return accounts

    def run(
        self,
        secret_key: str,
        master_password: str,
        email: str,
        force_mode: str = "auto",
        account_id: Optional[str] = None,
        account_uuid: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute full extraction & decryption pipeline.
        Returns a list of vaults with decrypted items formatted for 1PUX.
        """
        if force_mode != "raw":
            try:
                return self._extract_via_sqlite(
                    secret_key,
                    master_password,
                    email,
                    account_id=account_id,
                    account_uuid=account_uuid,
                )
            except Exception as e:
                if force_mode == "sqlite":
                    raise
                print(f"[!] SQLite structured extraction failed ({e}), falling back to raw stream scan...")

        return self._extract_via_raw_scan(secret_key, master_password, email)

    # =========================================================================
    # Strategy 1: Clean SQLite Structured Extraction (1Password 8 + 1Password 7)
    # =========================================================================
    def _extract_via_sqlite(
        self,
        secret_key: str,
        master_password: str,
        email: str,
        account_id: Optional[str] = None,
        account_uuid: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        uri = f"file:{self.db_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check existing tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"].lower(): row["name"] for row in cursor.fetchall()}

        # Check if 1Password 8 schema (objects_associated + vaults + items)
        if "objects_associated" in tables and "vaults" in tables and "items" in tables:
            return self._extract_op8(
                conn,
                secret_key,
                master_password,
                email,
                target_account=account_uuid or account_id,
            )

        # Check if 1Password 7 schema (keysets + vaults + items)
        keysets_table = tables.get("keysets") or tables.get("keyset")
        vaults_table = tables.get("vaults") or tables.get("vault")
        items_table = tables.get("items") or tables.get("item")

        if keysets_table and vaults_table and items_table:
            return self._extract_op7(
                conn,
                keysets_table,
                vaults_table,
                items_table,
                secret_key,
                master_password,
                email,
                account_id=account_id,
                account_uuid=account_uuid,
            )

        raise ValueError(
            f"Required tables not found in SQLite DB. Available: {list(tables.keys())}"
        )

    # =========================================================================
    # 1Password 8 Extraction Implementation
    # =========================================================================
    def _extract_op8(
        self,
        conn: sqlite3.Connection,
        secret_key: str,
        master_password: str,
        email: str,
        target_account: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        cursor = conn.cursor()

        # If target account not specified, discover default
        if not target_account:
            cursor.execute("SELECT account_uuid FROM accounts LIMIT 1")
            row = cursor.fetchone()
            if row:
                target_account = row[0]

        # 1. Read keysets from objects_associated (type 36)
        if target_account:
            cursor.execute(
                "SELECT data FROM objects_associated WHERE account_uuid = ? AND (type = 36 OR data LIKE '%encSymKey%')",
                (target_account,),
            )
        else:
            cursor.execute(
                "SELECT data FROM objects_associated WHERE type = 36 OR data LIKE '%encSymKey%'"
            )

        keyset_rows = cursor.fetchall()
        if not keyset_rows:
            raise ValueError(f"No keysets found for account '{target_account}'.")

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

            # Check if this encSymKey has 2SKD derivation parameters (p2s, p2c)
            if enc_sym and "p2s" in enc_sym and "data" in enc_sym:
                p2s = decode_payload(enc_sym["p2s"])
                p2c = int(enc_sym["p2c"])
                alg = enc_sym.get("alg") or "PBES2g-HS256"
                iv = decode_payload(enc_sym["iv"])
                ct = decode_payload(enc_sym["data"])

                try:
                    muk_cand = compute_2skd(secret_key, master_password, email, p2s, p2c, alg)
                    dec_mk = dec_aes_gcm(ct, muk_cand, iv)
                    mk_dict = json.loads(dec_mk.decode("utf-8"))
                    muk = muk_cand
                    mk_key_bytes = b64url_decode(mk_dict["k"])

                    # If this block also has encPriKey, decrypt it
                    if enc_pri and "data" in enc_pri and "iv" in enc_pri:
                        p_iv = decode_payload(enc_pri["iv"])
                        p_ct = decode_payload(enc_pri["data"])
                        dec_rsa = dec_aes_gcm(p_ct, mk_key_bytes, p_iv)
                        rsa_key = parse_rsa_jwk(dec_rsa)
                    break
                except Exception:
                    continue

        if not mk_dict or not mk_key_bytes:
            raise ValueError(
                "Failed to derive MUK or decrypt Master Key. Please verify Secret Key, Master Password, and Email."
            )

        # If RSA key was in another row, find it
        if not rsa_key:
            for r in keyset_rows:
                obj = _safe_json_parse(r[0])
                if not obj:
                    continue
                enc_pri = obj.get("encPriKey") or obj.get("enc_pri_key")
                if enc_pri and "data" in enc_pri and "iv" in enc_pri:
                    p_iv = decode_payload(enc_pri["iv"])
                    p_ct = decode_payload(enc_pri["data"])
                    try:
                        dec_rsa = dec_aes_gcm(p_ct, mk_key_bytes, p_iv)
                        rsa_key = parse_rsa_jwk(dec_rsa)
                        break
                    except Exception:
                        continue

        if not rsa_key:
            raise ValueError("Failed to decrypt RSA private key with Master Key.")

        # 2. Read & Decrypt Vaults
        if target_account:
            cursor.execute(
                "SELECT vault_uuid, data FROM vaults WHERE account_uuid = ?",
                (target_account,),
            )
        else:
            cursor.execute("SELECT vault_uuid, data FROM vaults")

        vault_rows = cursor.fetchall()
        vaults_data = []
        vault_key_map = {}  # vault_uuid -> {key_bytes, target_list}

        for v_uuid, v_raw in vault_rows:
            v_dict = _safe_json_parse(v_raw) or {}
            enc_vk = v_dict.get("enc_vault_key") or v_dict.get("encVaultKey")
            enc_attrs = v_dict.get("enc_attrs") or v_dict.get("encAttrs")

            if not enc_vk or "data" not in enc_vk:
                continue

            # Decrypt vault key via RSA-OAEP
            try:
                ct = decode_payload(enc_vk["data"])
                dec_vk_json = dec_rsa_oaep(rsa_key, ct)
                vk_obj = json.loads(dec_vk_json.decode("utf-8"))
                vk_bytes = b64url_decode(vk_obj["k"])
            except Exception:
                # Vault belongs to another account/key, skip cleanly
                continue

            # Decrypt vault attributes (name, desc)
            v_attrs = {"name": f"Vault {v_uuid[:8]}", "desc": ""}
            if enc_attrs and "data" in enc_attrs and "iv" in enc_attrs:
                try:
                    iv = decode_payload(enc_attrs["iv"])
                    ct = decode_payload(enc_attrs["data"])
                    dec_attrs = dec_aes_gcm(ct, vk_bytes, iv)
                    v_attrs = json.loads(dec_attrs.decode("utf-8"))
                except Exception:
                    pass

            vault_entry = {
                "attrs": {
                    "uuid": v_uuid,
                    "name": v_attrs.get("name", "Unnamed Vault"),
                    "desc": v_attrs.get("desc", ""),
                },
                "items": [],
            }
            vaults_data.append(vault_entry)
            vault_key_map[v_uuid] = {
                "key_bytes": vk_bytes,
                "target_list": vault_entry["items"],
            }

        # 3. Read & Decrypt Items
        if target_account:
            cursor.execute(
                "SELECT item_uuid, vault_uuid, data FROM items WHERE account_uuid = ?",
                (target_account,),
            )
        else:
            cursor.execute("SELECT item_uuid, vault_uuid, data FROM items")

        item_rows = cursor.fetchall()
        for i_uuid, v_uuid, i_raw in item_rows:
            vk_info = vault_key_map.get(v_uuid)
            if not vk_info:
                continue

            vk_bytes = vk_info["key_bytes"]
            i_dict = _safe_json_parse(i_raw) or {}

            category_uuid = i_dict.get("category_uuid") or "001"
            updated_at = i_dict.get("updated_at")

            # Decrypt overview (title, url, ainfo)
            overview_obj = {}
            raw_overview = i_dict.get("overview")
            if isinstance(raw_overview, dict) and "data" in raw_overview and "iv" in raw_overview:
                try:
                    iv = decode_payload(raw_overview["iv"])
                    ct = decode_payload(raw_overview["data"])
                    overview_obj = json.loads(dec_aes_gcm(ct, vk_bytes, iv).decode("utf-8"))
                except Exception:
                    pass

            # Decrypt details (fields, passwords, notes)
            details_obj = {}
            raw_details = i_dict.get("details")
            if isinstance(raw_details, dict) and "data" in raw_details and "iv" in raw_details:
                try:
                    iv = decode_payload(raw_details["iv"])
                    ct = decode_payload(raw_details["data"])
                    details_obj = json.loads(dec_aes_gcm(ct, vk_bytes, iv).decode("utf-8"))
                except Exception:
                    pass

            if overview_obj or details_obj:
                item_entry = {
                    "id": i_uuid,
                    "categoryUuid": str(category_uuid),
                    "overview": overview_obj,
                    "details": details_obj,
                }
                if updated_at:
                    item_entry["updatedAt"] = updated_at
                vk_info["target_list"].append(item_entry)

        conn.close()
        return vaults_data

    # =========================================================================
    # 1Password 7 Extraction Implementation
    # =========================================================================
    def _extract_op7(
        self,
        conn: sqlite3.Connection,
        keysets_table: str,
        vaults_table: str,
        items_table: str,
        secret_key: str,
        master_password: str,
        email: str,
        account_id: Optional[str] = None,
        account_uuid: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        cursor = conn.cursor()

        cursor.execute(f"PRAGMA table_info({keysets_table})")
        k_cols = {r["name"].lower(): r["name"] for r in cursor.fetchall()}
        acc_k_col = k_cols.get("account_id") or k_cols.get("account_uuid")

        keyset_rows = []
        if acc_k_col and (account_id or account_uuid):
            target_acc = account_id or account_uuid
            cursor.execute(f"SELECT * FROM {keysets_table} WHERE {acc_k_col} = ?", (target_acc,))
            keyset_rows = cursor.fetchall()

        if not keyset_rows:
            cursor.execute(f"SELECT * FROM {keysets_table}")
            keyset_rows = cursor.fetchall()

        if not keyset_rows:
            raise ValueError("No keysets found in database.")

        muk = None
        mk_dict = None
        mk_key_bytes = None

        for row in keyset_rows:
            row_dict = dict(row)
            enc_sym = _safe_json_parse(row_dict.get("enc_sym_key"))
            if not enc_sym:
                continue

            p2s_raw = enc_sym.get("p2s")
            p2c_raw = enc_sym.get("p2c")
            alg = enc_sym.get("alg") or "PBES2g-HS256"
            iv_raw = enc_sym.get("iv")
            data_raw = enc_sym.get("data")

            if not (p2s_raw and p2c_raw and iv_raw and data_raw):
                continue

            p2s = decode_payload(p2s_raw)
            p2c = int(p2c_raw)
            iv = decode_payload(iv_raw)
            ct = decode_payload(data_raw)

            try:
                muk_candidate = compute_2skd(secret_key, master_password, email, p2s, p2c, alg)
                decrypted_mk = dec_aes_gcm(ct, muk_candidate, iv)
                mk_dict = json.loads(decrypted_mk.decode("utf-8"))
                muk = muk_candidate
                mk_key_bytes = b64url_decode(mk_dict["k"])
                break
            except Exception:
                continue

        if not mk_dict or not mk_key_bytes:
            raise ValueError(
                "Failed to derive MUK / decrypt Master Key. Please check your Secret Key, Master Password, and Email."
            )

        mk_kid = mk_dict.get("kid", "")

        rsa_key = None
        for row in keyset_rows:
            row_dict = dict(row)
            enc_pri = _safe_json_parse(row_dict.get("enc_pri_key"))
            if not enc_pri:
                continue
            if mk_kid and enc_pri.get("kid") and enc_pri.get("kid") != mk_kid:
                continue

            iv = decode_payload(enc_pri["iv"])
            ct = decode_payload(enc_pri["data"])
            try:
                decrypted_rsa_jwk = dec_aes_gcm(ct, mk_key_bytes, iv)
                rsa_key = parse_rsa_jwk(decrypted_rsa_jwk)
                break
            except Exception:
                continue

        if not rsa_key:
            raise ValueError("Failed to decrypt account RSA private key with Master Key.")

        cursor.execute(f"PRAGMA table_info({vaults_table})")
        v_cols = {r["name"].lower(): r["name"] for r in cursor.fetchall()}
        acc_v_col = v_cols.get("account_id") or v_cols.get("account_uuid")

        vault_rows = []
        if acc_v_col and (account_id or account_uuid):
            target_acc = account_id or account_uuid
            cursor.execute(f"SELECT * FROM {vaults_table} WHERE {acc_v_col} = ?", (target_acc,))
            vault_rows = cursor.fetchall()

        if not vault_rows:
            cursor.execute(f"SELECT * FROM {vaults_table}")
            vault_rows = cursor.fetchall()

        vaults_data = []
        vault_key_map = {}

        for v_row in vault_rows:
            v_dict = dict(v_row)
            v_uuid = v_dict.get("uuid") or str(v_dict.get("id"))
            enc_vault_key = _safe_json_parse(v_dict.get("enc_vault_key"))
            enc_attrs = _safe_json_parse(v_dict.get("enc_attrs"))

            if not enc_vault_key:
                continue

            try:
                ct = decode_payload(enc_vault_key.get("data"))
                decrypted_vk_json = dec_rsa_oaep(rsa_key, ct)
                vk_obj = json.loads(decrypted_vk_json.decode("utf-8"))
                vk_bytes = b64url_decode(vk_obj["k"])
                vk_kid = vk_obj.get("kid", v_uuid)
            except Exception:
                continue

            v_attrs = {"name": "Vault", "desc": ""}
            if enc_attrs:
                try:
                    iv = decode_payload(enc_attrs["iv"])
                    ct = decode_payload(enc_attrs["data"])
                    decrypted_attrs = dec_aes_gcm(ct, vk_bytes, iv)
                    v_attrs = json.loads(decrypted_attrs.decode("utf-8"))
                except Exception:
                    pass

            vault_info = {
                "attrs": {
                    "uuid": v_uuid,
                    "name": v_attrs.get("name", "Unnamed Vault"),
                    "desc": v_attrs.get("desc", ""),
                },
                "items": [],
            }
            vaults_data.append(vault_info)
            vault_key_map[v_uuid] = {
                "key_bytes": vk_bytes,
                "kid": vk_kid,
                "target_list": vault_info["items"],
            }

        cursor.execute(f"SELECT * FROM {items_table}")
        item_rows = cursor.fetchall()

        for i_row in item_rows:
            i_dict = dict(i_row)
            i_uuid = i_dict.get("uuid") or str(i_dict.get("id"))
            v_uuid = i_dict.get("vault_uuid") or i_dict.get("vault_id")
            category_id = i_dict.get("category_id") or i_dict.get("category_uuid") or "001"
            updated_at = i_dict.get("updated_at")

            vk_info = vault_key_map.get(v_uuid)
            if not vk_info and len(vault_key_map) == 1:
                vk_info = next(iter(vault_key_map.values()))

            if not vk_info:
                continue

            vk_bytes = vk_info["key_bytes"]

            overview_obj = {}
            raw_overview = _safe_json_parse(i_dict.get("overview"))
            if raw_overview and "data" in raw_overview and "iv" in raw_overview:
                try:
                    iv = decode_payload(raw_overview["iv"])
                    ct = decode_payload(raw_overview["data"])
                    dec = dec_aes_gcm(ct, vk_bytes, iv)
                    overview_obj = json.loads(dec.decode("utf-8"))
                except Exception:
                    pass

            details_obj = {}
            raw_details = _safe_json_parse(i_dict.get("details"))
            if raw_details and "data" in raw_details and "iv" in raw_details:
                try:
                    iv = decode_payload(raw_details["iv"])
                    ct = decode_payload(raw_details["data"])
                    dec = dec_aes_gcm(ct, vk_bytes, iv)
                    details_obj = json.loads(dec.decode("utf-8"))
                except Exception:
                    pass

            if overview_obj or details_obj:
                item_entry = {
                    "id": i_uuid,
                    "categoryUuid": str(category_id),
                    "overview": overview_obj,
                    "details": details_obj,
                }
                if updated_at:
                    item_entry["updatedAt"] = updated_at
                vk_info["target_list"].append(item_entry)

        conn.close()
        return vaults_data

    # =========================================================================
    # Strategy 2: Robust Raw Stream Scanner (Fallback for WAL/corrupt files)
    # =========================================================================
    def _extract_via_raw_scan(
        self, secret_key: str, master_password: str, email: str
    ) -> List[Dict[str, Any]]:
        raw_bytes = self.db_path.read_bytes()
        text = raw_bytes.decode("utf-8", errors="ignore")

        def find_json_blocks(keyword: str) -> List[Dict[str, Any]]:
            results = []
            pos = 0
            while True:
                idx = text.find(keyword, pos)
                if idx == -1:
                    break
                start = text.rfind("{", max(0, idx - 200), idx)
                if start != -1:
                    brace_count = 0
                    end = start
                    while end < len(text) and end < start + 16000:
                        ch = text[end]
                        if ch == "{":
                            brace_count += 1
                        elif ch == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                chunk = text[start : end + 1]
                                try:
                                    parsed = json.loads(chunk)
                                    results.append(parsed)
                                except Exception:
                                    pass
                                break
                        end += 1
                pos = idx + len(keyword)
            return results

        sym_blocks = find_json_blocks("enc_sym_key") + find_json_blocks("encSymKey")
        muk = None
        mk_dict = None
        mk_key_bytes = None

        for block in sym_blocks:
            enc_sym = (
                block.get("enc_sym_key")
                or block.get("encSymKey")
                or block
            )
            if isinstance(enc_sym, dict) and "p2s" in enc_sym and "data" in enc_sym:
                p2s = decode_payload(enc_sym["p2s"])
                p2c = int(enc_sym["p2c"])
                alg = enc_sym.get("alg", "PBES2g-HS256")
                iv = decode_payload(enc_sym["iv"])
                ct = decode_payload(enc_sym["data"])

                try:
                    muk_cand = compute_2skd(secret_key, master_password, email, p2s, p2c, alg)
                    dec_mk = dec_aes_gcm(ct, muk_cand, iv)
                    mk_dict = json.loads(dec_mk.decode("utf-8"))
                    muk = muk_cand
                    mk_key_bytes = b64url_decode(mk_dict["k"])
                    break
                except Exception:
                    continue

        if not mk_dict or not mk_key_bytes:
            raise ValueError("Raw scan: failed to derive MUK or decrypt Master Key.")

        mk_kid = mk_dict.get("kid", "")

        pri_blocks = find_json_blocks("enc_pri_key") + find_json_blocks("encPriKey")
        rsa_key = None
        for block in pri_blocks:
            enc_pri = (
                block.get("enc_pri_key")
                or block.get("encPriKey")
                or block
            )
            if isinstance(enc_pri, dict) and "data" in enc_pri:
                if mk_kid and enc_pri.get("kid") and enc_pri.get("kid") != mk_kid:
                    continue
                try:
                    iv = decode_payload(enc_pri["iv"])
                    ct = decode_payload(enc_pri["data"])
                    dec_rsa = dec_aes_gcm(ct, mk_key_bytes, iv)
                    rsa_key = parse_rsa_jwk(dec_rsa)
                    break
                except Exception:
                    continue

        if not rsa_key:
            raise ValueError("Raw scan: failed to decrypt RSA private key.")

        vault_blocks = find_json_blocks("enc_vault_key") + find_json_blocks("encVaultKey")
        vaults_data = []
        vault_key_map = {}

        for block in vault_blocks:
            enc_vk = (
                block.get("enc_vault_key")
                or block.get("encVaultKey")
                or block
            )
            if isinstance(enc_vk, dict) and "data" in enc_vk:
                try:
                    ct = decode_payload(enc_vk["data"])
                    dec_vk = dec_rsa_oaep(rsa_key, ct)
                    vk_obj = json.loads(dec_vk.decode("utf-8"))
                    vk_bytes = b64url_decode(vk_obj["k"])
                    vk_kid = vk_obj.get("kid", f"vault-{len(vaults_data)+1}")

                    vault_entry = {
                        "attrs": {"uuid": vk_kid, "name": f"Vault {vk_kid[:8]}", "desc": ""},
                        "items": [],
                    }
                    vaults_data.append(vault_entry)
                    vault_key_map[vk_kid] = {
                        "key_bytes": vk_bytes,
                        "target_list": vault_entry["items"],
                    }
                except Exception:
                    continue

        if not vaults_data:
            raise ValueError("Raw scan: failed to decrypt any vault keys.")

        all_item_blocks = find_json_blocks('"kid"')
        for item_block in all_item_blocks:
            kid = item_block.get("kid")
            if kid in vault_key_map and "iv" in item_block and "data" in item_block:
                vk_bytes = vault_key_map[kid]["key_bytes"]
                try:
                    iv = decode_payload(item_block["iv"])
                    ct = decode_payload(item_block["data"])
                    decrypted_json = json.loads(dec_aes_gcm(ct, vk_bytes, iv).decode("utf-8"))

                    if "title" in decrypted_json or "url" in decrypted_json or "ainfo" in decrypted_json:
                        vault_key_map[kid]["target_list"].append({
                            "id": f"item-{len(vault_key_map[kid]['target_list'])+1}",
                            "overview": decrypted_json,
                            "details": {},
                        })
                    elif "fields" in decrypted_json or "notesPlain" in decrypted_json:
                        vault_key_map[kid]["target_list"].append({
                            "id": f"item-{len(vault_key_map[kid]['target_list'])+1}",
                            "overview": {"title": "Decrypted Item"},
                            "details": decrypted_json,
                        })
                except Exception:
                    continue

        return vaults_data
