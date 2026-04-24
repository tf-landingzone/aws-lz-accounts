#!/usr/bin/env python3
"""
HCL2 tfvars writer — serialize Python dicts to Terraform .tfvars format.

Supports: str, int, float, bool, None, list, dict (nested).

Usage:
    from hcl_writer import write_tfvars, dict_to_hcl

    write_tfvars({"account_id": "123456789012", "enable": True}, "out.tfvars")
    hcl_string = dict_to_hcl({"key": "value"})
"""

import json
from pathlib import Path


def _hcl_value(value, indent: int = 0) -> str:
    """Convert a Python value to its HCL2 representation."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
        return f'"{escaped}"'
    if isinstance(value, list):
        if not value:
            return "[]"
        items = [_hcl_value(v, indent + 2) for v in value]
        # Short lists on one line, long lists multi-line
        one_line = f"[{', '.join(items)}]"
        if len(one_line) < 80 and "\n" not in one_line:
            return one_line
        pad = " " * (indent + 2)
        lines = [f"{pad}{item}," for item in items]
        return "[\n" + "\n".join(lines) + "\n" + " " * indent + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        return _hcl_block(value, indent)
    # Fallback: JSON-encode unknown types
    return json.dumps(value)


def _hcl_block(d: dict, indent: int = 0) -> str:
    """Convert a dict to an HCL2 block { key = value }."""
    pad = " " * (indent + 2)
    lines = []
    for key, val in d.items():
        hcl_val = _hcl_value(val, indent + 2)
        # Keys with special characters need quotes
        if not key.replace("_", "").replace("-", "").isalnum():
            key = f'"{key}"'
        lines.append(f"{pad}{key} = {hcl_val}")
    return "{\n" + "\n".join(lines) + "\n" + " " * indent + "}"


def dict_to_hcl(data: dict) -> str:
    """Convert a flat dict of tfvars to HCL2 format string.

    Top-level keys become variable assignments:
        key = "value"
        nested = {
          inner = "val"
        }
    """
    parts = []
    for key, value in data.items():
        hcl_val = _hcl_value(value, 0)
        parts.append(f"{key} = {hcl_val}")
    return "\n\n".join(parts) + "\n"


def write_tfvars(data: dict, path) -> None:
    """Write a dict to a .tfvars file in HCL2 format."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(dict_to_hcl(data))
