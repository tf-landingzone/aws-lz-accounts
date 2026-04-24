#!/usr/bin/env python3
"""
Resolve account → policies + SSO assignments + security baseline
from account_policy_map.yaml.

Given an account_id and account_name, determines:
  1. Which IAM policies to push
  2. Which SSO group + permission set to assign
  3. Which security baseline configuration to apply

Writes a Terraform tfvars.json that the account-setup pipeline consumes.

Usage:
    python3 resolve_account.py <account_id> <account_name> [--environment ENV]
    python3 resolve_account.py <account_id> <account_name> --dry-run

Example:
    python3 resolve_account.py 123456789012 prod-app-001
    python3 resolve_account.py 123456789012 dev-sandbox-001 --environment development
    python3 resolve_account.py 123456789012 prod-app-001 --dry-run

Output:
    terraform/account-setup/terraform.tfvars
"""

import argparse
import copy
import difflib
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required.  Install with:  pip install pyyaml")

from hcl_writer import write_tfvars

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
MAP_FILE = ROOT / "account_policy_map.yaml"
OUTPUT_FILE = ROOT / "stacks" / "account-setup" / "terraform.tfvars"

# Valid environments — must match Terraform variable validation
VALID_ENVIRONMENTS = {"production", "staging", "development", "sandbox"}

# Default security baseline per environment
SECURITY_BASELINE_DEFAULTS = {
    "production": {
        "enable_password_policy": True,
        "enable_ebs_encryption": True,
        "enable_s3_public_access_block": True,
        "enable_access_analyzer": True,
        "password_policy": {
            "minimum_length": 14,
            "require_lowercase": True,
            "require_uppercase": True,
            "require_numbers": True,
            "require_symbols": True,
            "allow_users_to_change": True,
            "max_age_days": 90,
            "reuse_prevention": 24,
            "hard_expiry": False,
        },
    },
    "staging": {
        "enable_password_policy": True,
        "enable_ebs_encryption": True,
        "enable_s3_public_access_block": True,
        "enable_access_analyzer": True,
        "password_policy": {
            "minimum_length": 12,
            "require_lowercase": True,
            "require_uppercase": True,
            "require_numbers": True,
            "require_symbols": True,
            "allow_users_to_change": True,
            "max_age_days": 90,
            "reuse_prevention": 12,
            "hard_expiry": False,
        },
    },
    "development": {
        "enable_password_policy": True,
        "enable_ebs_encryption": True,
        "enable_s3_public_access_block": True,
        "enable_access_analyzer": False,
        "password_policy": {
            "minimum_length": 8,
            "require_lowercase": True,
            "require_uppercase": True,
            "require_numbers": True,
            "require_symbols": False,
            "allow_users_to_change": True,
            "max_age_days": 0,
            "reuse_prevention": 0,
            "hard_expiry": False,
        },
    },
    "sandbox": {
        "enable_password_policy": False,
        "enable_ebs_encryption": True,
        "enable_s3_public_access_block": True,
        "enable_access_analyzer": False,
        "password_policy": {},
    },
}


def load_map(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"ERROR: Mapping file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data:
        sys.exit(f"ERROR: {path} is empty or invalid YAML.")
    validate_mapping_structure(data, path)
    return data


def validate_mapping_structure(data: dict, path: Path) -> None:
    """Validate the top-level structure of account_policy_map.yaml."""
    if not isinstance(data, dict):
        sys.exit(f"ERROR: {path} must be a YAML mapping, got {type(data).__name__}")
    valid_keys = {"accounts", "prefix_rules", "default"}
    unknown = set(data.keys()) - valid_keys
    if unknown:
        sys.exit(f"ERROR: {path} has unknown top-level keys: {', '.join(sorted(unknown))}")
    if "accounts" in data and not isinstance(data["accounts"], dict):
        sys.exit(f"ERROR: 'accounts' must be a mapping in {path}")
    if "prefix_rules" in data and not isinstance(data["prefix_rules"], list):
        sys.exit(f"ERROR: 'prefix_rules' must be a list in {path}")
    for i, rule in enumerate(data.get("prefix_rules") or []):
        if not isinstance(rule, dict) or "prefix" not in rule:
            sys.exit(f"ERROR: prefix_rules[{i}] must be a mapping with a 'prefix' key in {path}")


def validate_account_id(account_id: str) -> None:
    if not re.match(r"^\d{12}$", account_id):
        sys.exit(f"ERROR: Account ID must be exactly 12 digits, got: {account_id}")


def validate_account_name(account_name: str) -> None:
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$", account_name):
        sys.exit(
            f"ERROR: Account name must be 3-50 chars, lowercase alphanumeric "
            f"with hyphens, got: {account_name}"
        )


def infer_environment(account_name: str) -> str:
    """Infer environment from account name prefix."""
    env_prefixes = {
        "prod-": "production",
        "production-": "production",
        "staging-": "staging",
        "stg-": "staging",
        "dev-": "development",
        "development-": "development",
        "sandbox-": "sandbox",
        "sbx-": "sandbox",
    }
    for prefix, env in env_prefixes.items():
        if account_name.startswith(prefix):
            return env
    return "production"  # Secure default


def validate_policy_files(resolved: dict) -> None:
    """Validate that all referenced policy files exist."""
    policies = resolved.get("policies", {})
    for key, policy in policies.items():
        policy_file = policy.get("file", "")
        if policy_file:
            full_path = ROOT / policy_file
            if not full_path.exists():
                sys.exit(
                    f"ERROR: Policy file not found: {full_path} "
                    f"(referenced by policy '{key}')"
                )


def resolve(account_id: str, account_name: str, mapping: dict) -> dict:
    """
    Resolution order:
      1. Exact account_id match in 'accounts'
      2. First matching prefix in 'prefix_rules'
      3. 'default' fallback
    """

    # 1. Exact account match
    accounts = mapping.get("accounts") or {}
    if account_id in accounts:
        print(f"  Matched: exact account ID {account_id}")
        return accounts[account_id]

    # 2. Prefix match on account_name (longest prefix first for deterministic matching)
    prefix_rules = sorted(
        (mapping.get("prefix_rules") or []),
        key=lambda r: len(r.get("prefix", "")),
        reverse=True,
    )
    for rule in prefix_rules:
        prefix = rule.get("prefix", "")
        if prefix and account_name.startswith(prefix):
            print(f"  Matched: prefix rule '{prefix}'")
            return {
                "policies": rule.get("policies", {}),
                "assignments": rule.get("assignments", {}),
                "security_baseline": rule.get("security_baseline"),
            }

    # 3. Default fallback
    default = mapping.get("default")
    if default:
        print(f"  Matched: default fallback")
        return default

    sys.exit(f"ERROR: No mapping found for account {account_id} ({account_name}).")


def resolve_security_baseline(environment: str, resolved: dict) -> dict:
    """
    Resolve security baseline config.
    Priority: explicit in mapping > environment defaults
    """
    # Start with environment defaults (deep copy to avoid mutating the global defaults)
    baseline = copy.deepcopy(SECURITY_BASELINE_DEFAULTS.get(environment, SECURITY_BASELINE_DEFAULTS["production"]))

    # Override with explicit settings from mapping if present
    explicit = resolved.get("security_baseline")
    if explicit and isinstance(explicit, dict):
        for key, value in explicit.items():
            if key == "password_policy" and isinstance(value, dict):
                baseline_pw = baseline.get("password_policy", {})
                if isinstance(baseline_pw, dict):
                    baseline_pw.update(value)
                    baseline["password_policy"] = baseline_pw
            else:
                baseline[key] = value

    return baseline


def _diff_tfvars(existing_path: Path, new_tfvars: dict) -> None:
    """Print a unified diff between the existing and computed tfvars.

    Serialises both sides to HCL via hcl_writer so the comparison is
    apples-to-apples (no JSON vs HCL noise).
    """
    from hcl_writer import dict_to_hcl

    new_text = dict_to_hcl(new_tfvars)

    if not existing_path.exists():
        print(f"  [NEW] No existing tfvars at {existing_path}")
        print("  Would create:")
        for line in new_text.splitlines():
            print(f"  + {line}")
        return

    old_text = existing_path.read_text(encoding="utf-8")
    diff = list(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"existing  {existing_path}",
            tofile="computed",
            n=3,
        )
    )

    if not diff:
        print("  [CLEAN] No changes")
        return

    print(f"  [CHANGED] diff ({len(diff)} lines):")
    for line in diff:
        # Colour output on terminals that support ANSI
        if sys.stdout.isatty():
            if line.startswith("+") and not line.startswith("+++"):
                print(f"\033[32m{line}\033[0m", end="")
            elif line.startswith("-") and not line.startswith("---"):
                print(f"\033[31m{line}\033[0m", end="")
            else:
                print(line, end="")
        else:
            print(line, end="")
    print()


def build_tfvars(
    account_id: str,
    account_name: str,
    environment: str,
    resolved: dict,
    security_baseline: dict,
) -> dict:
    """Build the Terraform variable structure for account-setup."""
    return {
        "account_id": account_id,
        "account_name": account_name,
        "environment": environment,
        "policies": resolved.get("policies", {}),
        "assignments": resolved.get("assignments", {}),
        "security_baseline": security_baseline,
        "tags": {
            "AccountId": account_id,
            "AccountName": account_name,
            "Environment": environment,
            "ManagedBy": "terraform",
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Resolve account policies, SSO, and security baseline"
    )
    parser.add_argument("account_id", help="AWS Account ID (12 digits)")
    parser.add_argument("account_name", help="Account name (e.g. prod-app-001)")
    parser.add_argument(
        "--environment",
        choices=sorted(VALID_ENVIRONMENTS),
        default=None,
        help="Override inferred environment (default: inferred from name)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print resolved config without writing file",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help=(
            "Show what would change vs the current accounts/<id>/terraform.tfvars. "
            "Does not write any files. Safe to run on any account at any time."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_FILE,
        help=f"Output file path (default: {OUTPUT_FILE})",
    )
    args = parser.parse_args()

    account_id = args.account_id.strip()
    account_name = args.account_name.strip()

    # Validate inputs
    validate_account_id(account_id)
    validate_account_name(account_name)

    # Resolve environment
    environment = args.environment or infer_environment(account_name)
    print(f"Resolving: {account_id} ({account_name}) [env={environment}]")

    # Load mapping and resolve
    mapping = load_map(MAP_FILE)
    resolved = resolve(account_id, account_name, mapping)

    # Validate policy files exist
    validate_policy_files(resolved)

    # Resolve security baseline
    security_baseline = resolve_security_baseline(environment, resolved)

    # Build tfvars
    tfvars = build_tfvars(account_id, account_name, environment, resolved, security_baseline)

    if args.dry_run:
        print("\n--- DRY RUN (would write to {}) ---".format(args.output))
        print(json.dumps(tfvars, indent=2))
        return

    if args.diff:
        existing = ROOT / "accounts" / account_id / "terraform.tfvars"
        print(f"\nPolicy diff for {account_id} ({account_name}) [env={environment}]:")
        _diff_tfvars(existing, tfvars)
        return

    write_tfvars(tfvars, args.output)

    print(f"✓ Generated {args.output}")
    print(f"  Environment        : {environment}")
    print(f"  Policies           : {len(tfvars['policies'])}")
    print(f"  Assignments        : {len(tfvars['assignments'])}")
    print(f"  Password policy    : {'enabled' if security_baseline.get('enable_password_policy') else 'disabled'}")
    print(f"  EBS encryption     : {'enabled' if security_baseline.get('enable_ebs_encryption') else 'disabled'}")
    print(f"  S3 public block    : {'enabled' if security_baseline.get('enable_s3_public_access_block') else 'disabled'}")
    print(f"  Access Analyzer    : {'enabled' if security_baseline.get('enable_access_analyzer') else 'disabled'}")


if __name__ == "__main__":
    main()
