# aws-lz-accounts

**GitOps data layer** for the AWS Landing Zone. Owns account request files, validation schemas, and the workflows that trigger account provisioning in `aws-lz-platform`.

---

## How to request a new AWS account

1. Copy `accounts/requests/prod-app-001.yaml.example` → create `accounts/requests/<your-account-name>.yaml`
2. Fill in the required fields
3. Open a Pull Request — the `request-validate` workflow auto-validates your YAML
4. Merge to `main` — the `account-setup` workflow triggers provisioning automatically

---

## Account request YAML format

```yaml
account_name: "prod-payments"          # unique, lowercase, hyphens only
email: "aws+prod-payments@acme.com"    # unique root email for the account
ou: "workloads_prod"                   # must match an OU in landing-zone.yaml
environment: "production"              # production | staging | development | sandbox

# Optional overrides (auto-resolved from account_policy_map.yaml if omitted)
# sso:
#   permission_set: "ProdAccess"
#   group_name: "AWS-Prod-Engineers"
# policies:
#   prod_restricted:
#     name: "ProdRestrictedAdmin"
#     file: "policies/prod_restricted.json"

tags:
  Team: "payments"
  CostCenter: "CC-1234"
```

---

## What happens after merge

```
PR merged to main
       │
       ▼
account-setup.yml (this repo)
       │
       ├─ resolve job
       │    ├── checkout aws-lz-accounts (account YAML + scripts)
       │    ├── checkout aws-lz-platform (Terraform stacks)
       │    └── python scripts/resolve_account.py → writes terraform.tfvars
       │                                           → uploads "account-tfvars" artifact
       │
       └─ deploy job
            └── calls aws-lz-platform/.github/workflows/account-deploy-reusable.yml
                   ├── terraform plan (downloads artifact)
                   ├── manual approval gate (production only)
                   └── terraform apply → pushes IAM policies + SSO + baseline into account
```

---

## Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `request-validate.yml` | PR opened/updated | Validates YAML against schema + checks name/email uniqueness |
| `account-setup.yml` | Push to main (accounts/requests/**) or manual | Resolves + deploys one account |
| `drift-sweep.yml` | Nightly (dispatches to platform) | Checks all accounts for config drift |

---

## Scripts

| Script | Purpose |
|---|---|
| `scripts/resolve_account.py` | Reads account YAML + `account_policy_map.yaml` → writes `terraform.tfvars` |
| `scripts/process_account_requests.py` | Batch processor — finds PENDING accounts and queues them |
| `scripts/cleanup_closed_account.py` | Removes account data after AWS account closure |
| `scripts/hcl_writer.py` | Helper — writes HCL-formatted tfvars files |

---

## Repo layout

```
aws-lz-accounts/
├── accounts/
│   └── requests/            ← Drop new YAML files here to request accounts
├── schemas/
│   └── account-request.schema.json   ← JSON Schema used by PR validation
├── scripts/                 ← Account data resolution + processing scripts
├── CODEOWNERS               ← Requires platform-team approval on all PRs
├── account_policy_map.yaml  ← Maps account name prefixes → policies + SSO
└── .github/workflows/       ← Caller workflows (not Terraform — that's in platform)
```

---

## Required GitHub Actions secrets

| Secret | Where to add | Value |
|---|---|---|
| `PLATFORM_WORKFLOW_TOKEN` | This repo settings | GitHub PAT with `repo` + `workflow` scope for `tf-landingzone` org |

> `AWS_ROLE_ARN` is **not** needed here — Terraform runs in `aws-lz-platform`, not this repo.
