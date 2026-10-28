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

