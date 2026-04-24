#!/usr/bin/env python3
"""
cleanup_closed_account.py

Cleans up Terraform state and account metadata when an AWS account has been
closed (suspended/removed from the Organization). Without this, orphaned
state files accumulate in the state bucket — at scale (10k+ accounts)
this becomes a real cost and audit liability.

Workflow:
    1. Verify account is closed via Organizations API (status SUSPENDED, or
       account no longer in Org).
    2. Move S3 state object to closed/ prefix (preserved for audit, not
       active).
    3. Remove DynamoDB lock entry if present.
    4. Move accounts/<id>/ directory under accounts/_closed/<id>/.
    5. Optionally archive the account request YAML.

Designed to be invoked manually or via a scheduled GHA workflow that
reconciles Organizations state vs. local accounts/ tree.

Usage:
    python3 scripts/cleanup_closed_account.py --account-id 123456789012
    python3 scripts/cleanup_closed_account.py --account-id 123456789012 --dry-run
    python3 scripts/cleanup_closed_account.py --reconcile  # find all closed accounts
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
STATE_BUCKET = "acme-lz-terraform-state"
STATE_KEY_PREFIX = "account-setup"
LOCK_TABLE = "acme-lz-terraform-locks"
ACCOUNTS_DIR = Path("accounts")
CLOSED_DIR = ACCOUNTS_DIR / "_closed"


def _validate_account_id(account_id: str) -> str:
    """Validate account_id is exactly 12 digits."""
    if not ACCOUNT_ID_RE.match(account_id):
        raise ValueError(f"Invalid account_id: {account_id!r} (must be 12 digits)")
    return account_id


def _get_org_account_status(account_id: str) -> str | None:
    """Return account status from AWS Organizations, or None if not present."""
    try:
        import boto3  # noqa: PLC0415
        from botocore.exceptions import ClientError  # noqa: PLC0415
    except ImportError:
        print("boto3 not installed; cannot verify account status.", file=sys.stderr)
        return None

    org = boto3.client("organizations")
    try:
        resp = org.describe_account(AccountId=account_id)
        return resp["Account"]["Status"]
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"AccountNotFoundException", "AWSOrganizationsNotInUseException"}:
            return None
        raise


def _list_provisioned_accounts() -> list[str]:
    """Return account IDs from local accounts/<id>/account.json files."""
    if not ACCOUNTS_DIR.is_dir():
        return []
    ids: list[str] = []
    for child in ACCOUNTS_DIR.iterdir():
        if not child.is_dir() or child.name.startswith("_"):
            continue
        if not ACCOUNT_ID_RE.match(child.name):
            continue
        if (child / "account.json").is_file():
            ids.append(child.name)
    return sorted(ids)


def _move_state_object(account_id: str, dry_run: bool) -> bool:
    """Move state file from active prefix to closed/ prefix in S3."""
    try:
        import boto3  # noqa: PLC0415
        from botocore.exceptions import ClientError  # noqa: PLC0415
    except ImportError:
        print("boto3 not installed; skipping S3 state move.", file=sys.stderr)
        return False

    src_key = f"{STATE_KEY_PREFIX}/{account_id}/terraform.tfstate"
    dst_key = f"closed/{STATE_KEY_PREFIX}/{account_id}/terraform.tfstate"
    s3 = boto3.client("s3")

    try:
        s3.head_object(Bucket=STATE_BUCKET, Key=src_key)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
            print(f"  no active state at s3://{STATE_BUCKET}/{src_key}")
            return False
        raise

    if dry_run:
        print(f"  DRY-RUN would move s3://{STATE_BUCKET}/{src_key} -> {dst_key}")
        return True

    s3.copy_object(
        Bucket=STATE_BUCKET,
        Key=dst_key,
        CopySource={"Bucket": STATE_BUCKET, "Key": src_key},
        MetadataDirective="COPY",
    )
    s3.delete_object(Bucket=STATE_BUCKET, Key=src_key)
    print(f"  moved state -> s3://{STATE_BUCKET}/{dst_key}")
    return True


def _remove_lock(account_id: str, dry_run: bool) -> bool:
    """Best-effort removal of any orphaned DynamoDB lock for this account state."""
    try:
        import boto3  # noqa: PLC0415
        from botocore.exceptions import ClientError  # noqa: PLC0415
    except ImportError:
        return False

    lock_id = f"{STATE_BUCKET}/{STATE_KEY_PREFIX}/{account_id}/terraform.tfstate-md5"
    if dry_run:
        print(f"  DRY-RUN would delete lock {lock_id} from {LOCK_TABLE}")
        return True
    ddb = boto3.client("dynamodb")
    try:
        ddb.delete_item(TableName=LOCK_TABLE, Key={"LockID": {"S": lock_id}})
        print(f"  removed lock {lock_id}")
        return True
    except ClientError as e:
        print(f"  warning: could not remove lock: {e}", file=sys.stderr)
        return False


def _archive_local_files(account_id: str, dry_run: bool) -> bool:
    """Move accounts/<id>/ to accounts/_closed/<id>/ for audit retention."""
    src = ACCOUNTS_DIR / account_id
    if not src.is_dir():
        return False
    dst = CLOSED_DIR / account_id
    if dry_run:
        print(f"  DRY-RUN would move {src} -> {dst}")
        return True
    CLOSED_DIR.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        print(f"  warning: {dst} already exists, skipping local archive", file=sys.stderr)
        return False
    src.rename(dst)
    print(f"  archived {src} -> {dst}")
    return True


def cleanup_account(account_id: str, dry_run: bool, force: bool) -> bool:
    """Run the full cleanup for one account. Returns True on full success."""
    account_id = _validate_account_id(account_id)
    print(f"\n[{account_id}] cleanup begin (dry_run={dry_run}, force={force})")

    if not force:
        status = _get_org_account_status(account_id)
        if status is not None and status != "SUSPENDED":
            print(
                f"  refusing to clean up: account status is {status} (not SUSPENDED). "
                "Use --force to override.",
                file=sys.stderr,
            )
            return False
        print(f"  account status: {status or 'NOT_IN_ORG'}")

    moved = _move_state_object(account_id, dry_run)
    _remove_lock(account_id, dry_run)
    archived = _archive_local_files(account_id, dry_run)

    print(f"[{account_id}] cleanup complete (state_moved={moved}, archived={archived})")
    return True


def reconcile(dry_run: bool, force: bool) -> int:
    """Walk local accounts/ and clean up any whose Org status is closed/missing."""
    local = _list_provisioned_accounts()
    print(f"Found {len(local)} provisioned accounts under {ACCOUNTS_DIR}/")
    closed = []
    for account_id in local:
        status = _get_org_account_status(account_id)
        if status is None or status == "SUSPENDED":
            print(f"  {account_id}: status={status or 'NOT_IN_ORG'} -> queue for cleanup")
            closed.append(account_id)
    if not closed:
        print("Nothing to reconcile — all local accounts are ACTIVE.")
        return 0
    failures = 0
    for account_id in closed:
        if not cleanup_account(account_id, dry_run=dry_run, force=force):
            failures += 1
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--account-id", help="Single account ID to clean up.")
    group.add_argument(
        "--reconcile",
        action="store_true",
        help="Scan accounts/ and clean up any whose Org status is closed/missing.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing them.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip the Organizations status check (use when API is unavailable).",
    )
    args = parser.parse_args(argv)

    if args.reconcile:
        return 1 if reconcile(args.dry_run, args.force) else 0

    ok = cleanup_account(args.account_id, dry_run=args.dry_run, force=args.force)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
