import copy
import time
from typing import Any, Dict, List, Optional, Tuple


def _get_timestamp(item: Dict[str, Any]) -> int:
    """Extract update timestamp from an item."""
    ts = item.get("updatedAt") or item.get("updated_at") or 0
    if isinstance(ts, (int, float)):
        return int(ts)
    if isinstance(ts, str):
        try:
            return int(float(ts))
        except ValueError:
            return 0
    return 0


def _merge_fields(
    fields_a: List[Dict[str, Any]],
    fields_b: List[Dict[str, Any]],
    fields_base: Optional[List[Dict[str, Any]]] = None,
    prefer_b: bool = True,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Merge fields inside details.fields by field key/name/designation.
    """
    logs = []
    
    def field_key(f: Dict[str, Any]) -> str:
        # Match by name, designation, or id
        return str(f.get("designation") or f.get("name") or f.get("id") or "")

    map_a = {field_key(f): f for f in fields_a if field_key(f)}
    map_b = {field_key(f): f for f in fields_b if field_key(f)}
    map_base = {field_key(f): f for f in (fields_base or []) if field_key(f)}

    all_keys = list(dict.fromkeys(list(map_a.keys()) + list(map_b.keys())))
    merged_fields = []

    for k in all_keys:
        fa = map_a.get(k)
        fb = map_b.get(k)
        fbase = map_base.get(k)

        if fa and not fb:
            # Only in A
            if fbase and fb is None:
                # Deleted in B
                logs.append(f"Field '{k}' was deleted in B")
                continue
            merged_fields.append(copy.deepcopy(fa))
        elif fb and not fa:
            # Only in B
            if fbase and fa is None:
                # Deleted in A
                logs.append(f"Field '{k}' was deleted in A")
                continue
            merged_fields.append(copy.deepcopy(fb))
        else:
            # In both A and B
            val_a = fa.get("value")
            val_b = fb.get("value")
            if val_a == val_b:
                merged_fields.append(copy.deepcopy(fb if prefer_b else fa))
            else:
                # Value conflict
                val_base = fbase.get("value") if fbase else None
                if fbase:
                    if val_a == val_base and val_b != val_base:
                        # Only B changed
                        merged_fields.append(copy.deepcopy(fb))
                        logs.append(f"Field '{k}' updated to B value")
                    elif val_b == val_base and val_a != val_base:
                        # Only A changed
                        merged_fields.append(copy.deepcopy(fa))
                        logs.append(f"Field '{k}' kept A value")
                    else:
                        # Both changed differently
                        chosen = fb if prefer_b else fa
                        merged_fields.append(copy.deepcopy(chosen))
                        logs.append(f"Field '{k}' conflict: A vs B -> chose {'B' if prefer_b else 'A'} (newer)")
                else:
                    chosen = fb if prefer_b else fa
                    merged_fields.append(copy.deepcopy(chosen))
                    logs.append(f"Field '{k}' conflict: A vs B -> chose {'B' if prefer_b else 'A'} (newer)")

    return merged_fields, logs


def merge_two_items(
    item_a: Dict[str, Any],
    item_b: Dict[str, Any],
    item_base: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Merge two items matching the same item ID.
    Supports 3-way merge if item_base is provided, or 2-way LWW + field-merge otherwise.
    """
    logs = []
    ts_a = _get_timestamp(item_a)
    ts_b = _get_timestamp(item_b)
    prefer_b = ts_b >= ts_a

    # Base item structure
    primary = copy.deepcopy(item_b if prefer_b else item_a)
    secondary = item_a if prefer_b else item_b

    title = primary.get("overview", {}).get("title") or secondary.get("overview", {}).get("title") or primary.get("id")

    # If identical, return early
    if item_a == item_b:
        return primary, logs

    # Merge overview: fill in missing fields from secondary
    ov_pri = primary.get("overview", {})
    ov_sec = secondary.get("overview", {})
    for k, v in ov_sec.items():
        if k not in ov_pri or not ov_pri[k]:
            ov_pri[k] = copy.deepcopy(v)

    # Merge details.fields
    det_pri = primary.setdefault("details", {})
    det_sec = secondary.get("details", {})
    fields_a = item_a.get("details", {}).get("fields", [])
    fields_b = item_b.get("details", {}).get("fields", [])
    fields_base = item_base.get("details", {}).get("fields", []) if item_base else None

    merged_fields, field_logs = _merge_fields(fields_a, fields_b, fields_base, prefer_b=prefer_b)
    det_pri["fields"] = merged_fields

    if field_logs:
        logs.append(f"Item '{title}' ({primary.get('id')}): " + "; ".join(field_logs))

    # Notes merge: if primary has no note but secondary does, copy it
    if not det_pri.get("notesPlain") and det_sec.get("notesPlain"):
        det_pri["notesPlain"] = det_sec["notesPlain"]

    # Sections merge: union sections
    sec_pri = det_pri.setdefault("sections", [])
    sec_sec = det_sec.get("sections", [])
    existing_sec_names = {s.get("name") or s.get("title") for s in sec_pri}
    for s in sec_sec:
        sname = s.get("name") or s.get("title")
        if sname and sname not in existing_sec_names:
            sec_pri.append(copy.deepcopy(s))
            existing_sec_names.add(sname)

    # Use latest timestamp
    primary["updatedAt"] = max(ts_a, ts_b)

    return primary, logs


def merge_vault_items(
    items_a: List[Dict[str, Any]],
    items_b: List[Dict[str, Any]],
    items_base: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    3-way or 2-way merge of item collections matching by item['id'].
    """
    map_a = {it["id"]: it for it in items_a if "id" in it}
    map_b = {it["id"]: it for it in items_b if "id" in it}
    map_base = {it["id"]: it for it in (items_base or []) if "id" in it}

    all_ids = list(dict.fromkeys(list(map_a.keys()) + list(map_b.keys())))

    merged_items = []
    stats = {
        "total_merged": 0,
        "only_in_a": 0,
        "only_in_b": 0,
        "in_both_identical": 0,
        "in_both_merged": 0,
        "conflict_logs": [],
    }

    for item_id in all_ids:
        in_a = map_a.get(item_id)
        in_b = map_b.get(item_id)
        in_base = map_base.get(item_id)

        if in_a and not in_b:
            stats["only_in_a"] += 1
            merged_items.append(copy.deepcopy(in_a))
        elif in_b and not in_a:
            stats["only_in_b"] += 1
            merged_items.append(copy.deepcopy(in_b))
        else:
            # In both A and B
            if in_a == in_b:
                stats["in_both_identical"] += 1
                merged_items.append(copy.deepcopy(in_a))
            else:
                stats["in_both_merged"] += 1
                merged_item, logs = merge_two_items(in_a, in_b, in_base)
                merged_items.append(merged_item)
                if logs:
                    stats["conflict_logs"].extend(logs)

    stats["total_merged"] = len(merged_items)
    return merged_items, stats
