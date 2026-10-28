import shutil
import subprocess
from typing import Optional


def create_item(vault: str, title: str, category: str, data: str) -> Optional[str]:
    """
    Optional helper to recreate an item using the official 1Password CLI ('op').
    Requires 'op' to be installed on the host system.
    """
    op_bin = shutil.which("op")
    if not op_bin:
        print("[!] 1Password CLI ('op') not found in PATH.")
        return None

    cmd = [
        op_bin,
        "item",
        "create",
        "--vault",
        vault,
        "--title",
        title,
        "--category",
        category,
    ]
    # If data contains extra parameters, pass them
    if data:
        cmd.extend(data.split())

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] Item created successfully: {title}")
        return res.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error creating item '{title}': {e.stderr}")
        return None
