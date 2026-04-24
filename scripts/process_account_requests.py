#!/usr/bin/env python3
"""
Process account requests from accounts/requests/*.yaml

For each YAML request file:
  1. Validates required fields
  2. Check if account already exists (via accounts/<name>/account.json)
  3. If new → outputs account creation params for Control Tower AFT
  4. If existing → resolves policies/SSO from account_policy_map.yaml
  5. Writes per-account tfvars to accounts/<account_id>/terraform.tfvars.json

Usage:
    python3 process_account_requests.py [--request FILE] [--account-id ID]

    # Process all pending requests:
    python3 process_account_requests.py

    # Process one specific request (after account_id is known):
    python3 process_account_requests.py --request accounts/requests/prod-app-001.yaml --account-id 123456789012
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required. Install with: pip install pyyaml")

ROOT = Path(__file__).parent.parent
REQUESTS_DIR = ROOT / "accounts" / "requests"
ACCOUNTS_DIR = ROOT / "accounts"
MAP_FILE = ROOT / "account_policy_map.yaml"
TF_DIR = ROOT / "stacks" / "account-setup"

# Import shared resolution logic
from resolve_account import resolve, infer_environment, resolve_security_baseline
from hcl_writer import write_tfvars


def load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def validate_request(request: dict, filepath: Path) -> None:
    """Validate required fields in account request."""
    required = ["account_name", "email", "ou", "environment"]
    missing = [f for f in required if not request.get(f)]
    if missing:
        sys.exit(f"ERROR: {filepath} missing required fields: {', '.join(missing)}")

    name = request["account_name"]
    if not re.match(r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$", name):
        sys.exit(f"ERROR: account_name '{name}' must be lowercase alphanumeric with hyphens, 3-50 chars")

    email = request["email"]
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        sys.exit(f"ERROR: Invalid email: {email}")

    valid_envs = ["production", "staging", "development", "sandbox"]
    if request["environment"] not in valid_envs:
        sys.exit(f"ERROR: environment must be one of: {', '.join(valid_envs)}")


def resolve_policies_and_sso(account_name: str, account_id: str, mapping: dict) -> dict:
    """Resolve policies + SSO + security baseline from account_policy_map.yaml."""
    try:
        return resolve(account_id, account_name, mapping)
    except SystemExit as e:
        sys.exit(
            f"ERROR: Policy resolution failed for {account_name} ({account_id}): {e}\n"
            f"Fix account_policy_map.yaml before provisioning this account."
        )


def build_account_tfvars(request: dict, account_id: str, resolved: dict) -> dict:
    """Build per-account terraform.tfvars.json."""
    # Use explicit SSO config from request, or fall back to resolved
    assignments = resolved.get("assignments", {})
    if request.get("sso"):
        sso = request["sso"]
        assignments = {
            "primary": {
                "permission_set_name": sso["permission_set"],
                "sso_group_name": sso["group_name"],
            }
        }

    # Use explicit policies from request, or fall back to resolved
    policies = resolved.get("policies", {})
    if request.get("policies"):
        policies = request["policies"]

    environment = request["environment"]
    security_baseline = resolve_security_baseline(environment, resolved)

    return {
        "account_id": account_id,
        "account_name": request["account_name"],
        "environment": environment,
        "policies": policies,
        "assignments": assignments,
        "security_baseline": security_baseline,
        "tags": {
            "AccountId": account_id,
            "AccountName": request["account_name"],
            "Environment": environment,
            "OU": request["ou"],
            "ManagedBy": "terraform",
            **(request.get("tags") or {}),
        },
    }


def build_account_factory_params(request: dict) -> dict:
    """Build parameters for Control Tower Account Factory creation."""
    return {
        "account_name": request["account_name"],
        "email": request["email"],
        "organizational_unit": request["ou"],
        "sso_user_email": request["email"],
        "sso_user_first_name": "AWS",
        "sso_user_last_name": request["account_name"],
        "tags": request.get("tags", {}),
    }


def save_account_state(account_id: str, account_name: str, request: dict, tfvars: dict):
    """Persist account state in accounts/<account_id>/."""
    acct_dir = ACCOUNTS_DIR / account_id
    acct_dir.mkdir(parents=True, exist_ok=True)

    # account.json — metadata
    meta = {
        "account_id": account_id,
        "account_name": account_name,
        "email": request["email"],
        "ou": request["ou"],
        "environment": request["environment"],
        "status": "provisioned",
        "tags": request.get("tags", {}),
    }
    with open(acct_dir / "account.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    # terraform.tfvars — what Terraform needs
    write_tfvars(tfvars, acct_dir / "terraform.tfvars")

    print(f"  Saved: {acct_dir}/account.json + terraform.tfvars")


def process_single_request(request_path: Path, account_id: str = None):
    """Process a single account request."""
    # Validate account_id early to prevent path traversal
    if account_id and not re.match(r"^\d{12}$", account_id):
        sys.exit(f"ERROR: Invalid account ID '{account_id}' — must be exactly 12 digits")

    request = load_yaml(request_path)
    validate_request(request, request_path)

    account_name = request["account_name"]
    print(f"\nProcessing: {account_name} ({request_path.name})")

    mapping = load_yaml(MAP_FILE)

    if not account_id:
        # Check if we already know this account
        for d in ACCOUNTS_DIR.iterdir():
            if d.is_dir() and (d / "account.json").exists():
                with open(d / "account.json", encoding="utf-8") as f:
                    meta = json.load(f)
                if meta and meta.get("account_name") == account_name:
                    account_id = meta["account_id"]
                    print(f"  Found existing account: {account_id}")
                    break

    if not account_id:
        # New account — output Account Factory params
        aft_params = build_account_factory_params(request)
        aft_file = ACCOUNTS_DIR / "pending" / f"{account_name}.json"
        aft_file.parent.mkdir(parents=True, exist_ok=True)
        with open(aft_file, "w", encoding="utf-8") as f:
            json.dump(aft_params, f, indent=2)
        print(f"  NEW ACCOUNT — written AFT params: {aft_file}")
        print(f"  Next: Create via Control Tower, then re-run with --account-id")
        return {"status": "pending", "account_name": account_name}

    # Existing account — resolve and build tfvars
    resolved = resolve_policies_and_sso(account_name, account_id, mapping)
    tfvars = build_account_tfvars(request, account_id, resolved)

    # Save per-account state
    save_account_state(account_id, account_name, request, tfvars)

    # Also write to the terraform/account-setup directory for immediate use
    TF_DIR.mkdir(parents=True, exist_ok=True)
    write_tfvars(tfvars, TF_DIR / "terraform.tfvars")
    print(f"  Written: {TF_DIR}/terraform.tfvars")

    return {"status": "ready", "account_id": account_id, "account_name": account_name}


def main():
    parser = argparse.ArgumentParser(description="Process account requests")
    parser.add_argument("--request", help="Specific request YAML file to process")
    parser.add_argument("--account-id", help="AWS Account ID (if already created)")
    args = parser.parse_args()

    if args.request:
        result = process_single_request(Path(args.request), args.account_id)
        print(f"\nResult: {json.dumps(result, indent=2)}")
        return

    # Process all .yaml files in requests/
    if not REQUESTS_DIR.exists():
        print("No requests directory found")
        return

    results = []
    for req_file in sorted(REQUESTS_DIR.glob("*.yaml")):
        result = process_single_request(req_file)
        results.append(result)

    print(f"\n{'='*60}")
    print(f"Processed {len(results)} request(s)")
    pending = [r for r in results if r["status"] == "pending"]
    ready = [r for r in results if r["status"] == "ready"]
    if pending:
        print(f"  Pending (need account creation): {len(pending)}")
    if ready:
        print(f"  Ready (can apply baseline): {len(ready)}")


if __name__ == "__main__":
    main()
