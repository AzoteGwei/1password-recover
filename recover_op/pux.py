import json
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

UnionPath = Union[str, Path]


def build_1pux_package(
    output_path: UnionPath,
    vaults: List[Dict[str, Any]],
    email: str = "",
    account_uuid: str = "",
    account_name: str = "",
) -> Path:
    """
    Assemble decrypted 1Password vaults and items into a standard .1pux (ZIP) archive.
    """
    out_file = Path(output_path)
    if not out_file.name.endswith(".1pux"):
        out_file = out_file.with_suffix(".1pux")

    now = int(time.time())

    attributes = {
        "version": 3,
        "description": "1Password Unencrypted Export",
        "createdAt": now,
    }

    account_data = {
        "attrs": {
            "accountUuid": account_uuid or "recovered-account-0001",
            "name": account_name or email or "Recovered Account",
            "email": email or "user@example.com",
        },
        "vaults": vaults,
    }

    export_data = {
        "accounts": [account_data],
    }

    with zipfile.ZipFile(out_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1. export.attributes
        zf.writestr(
            "export.attributes",
            json.dumps(attributes, indent=2, ensure_ascii=False).encode("utf-8"),
        )

        # 2. export.data
        zf.writestr(
            "export.data",
            json.dumps(export_data, indent=2, ensure_ascii=False).encode("utf-8"),
        )

        # 3. files/ directory entry
        zf.writestr("files/", "")

    return out_file


def load_items_from_file(file_path: UnionPath) -> List[Dict[str, Any]]:
    """
    Extract items from an existing .1pux (ZIP) archive or a .json file.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Case 1: .1pux or ZIP file
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, "r") as zf:
            if "export.data" in zf.namelist():
                content = zf.read("export.data").decode("utf-8")
                data = json.loads(content)
                items = []
                for acc in data.get("accounts", []):
                    for v in acc.get("vaults", []):
                        items.extend(v.get("items", []))
                return items

    # Case 2: Plain JSON file
    content = path.read_text(encoding="utf-8")
    data = json.loads(content)

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "items" in data and isinstance(data["items"], list):
            return data["items"]
        if "accounts" in data:
            items = []
            for acc in data.get("accounts", []):
                for v in acc.get("vaults", []):
                    items.extend(v.get("items", []))
            return items

    raise ValueError(f"Could not extract item list from {path.name}")
