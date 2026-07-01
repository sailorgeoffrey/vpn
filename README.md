# Personal VPN

A personal WireGuard VPN running on your own AWS account, deployed with CDK.
Spin it up when you need it, terminate it when you don't — no idle compute cost.

## Why

Commercial VPN products (NordVPN, etc.) aren't approved for use on corporate
infrastructure, but AWS is. This solution routes all traffic from a Tart VM
through an EC2 instance you control, in a region of your choice.

## How it works

```
Tart VM ──── WireGuard tunnel ──── EC2 (t4g.nano) ──── Internet
               UDP 51820              eu-central-1
                                      us-east-1
```

- **CDK** provisions one stack per region: a KMS key, security group, IAM role,
  and Launch Template. Nothing runs until you need it.
- At deploy time a **Lambda custom resource** generates a Curve25519 client
  keypair and stores it encrypted in SSM Parameter Store.
- When you run `connect.sh up`, it launches the EC2 instance from the Launch
  Template. The instance generates its own server keypair on first boot, stores
  it in SSM, configures WireGuard, and enables IP forwarding + NAT.
- `connect.sh` fetches both keypairs from SSM, writes a local `wg0.conf`, and
  brings up the tunnel. All traffic from the VM exits through the EC2 instance.
- `connect.sh down` tears down the tunnel and **terminates the instance** — you
  pay only while the tunnel is active.

### Key security properties

- The **client private key** is generated in Lambda at deploy time, stored
  KMS-encrypted in SSM, and never written to disk on any machine long-term. It
  is fetched into a tmpfs-backed config file only while the tunnel is up.
- The **server private key** is generated on the EC2 instance itself and stored
  KMS-encrypted in SSM. It never leaves AWS.
- Both keys are protected by a per-region KMS key with automatic annual
  rotation.
- The EC2 instance has no SSH access and no inbound rules other than UDP 51820.

## Prerequisites

### On your laptop (for deployment)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) configured with a profile that has permissions to deploy CDK stacks
- [Node.js 20+](https://nodejs.org)

### On the Tart VM (for connecting)
- `wireguard-tools` — `sudo apt-get install wireguard-tools`
- AWS CLI v2 configured with credentials that can read SSM parameters and launch EC2 instances
- `jq`

## First-time setup

### 1. Bootstrap CDK (once per account/region)

```bash
npx cdk bootstrap aws://ACCOUNT_ID/eu-central-1
npx cdk bootstrap aws://ACCOUNT_ID/us-east-1
```

### 2. Deploy

```bash
npm install
npx cdk deploy --all        # both regions
npx cdk deploy VpnEu        # EU only
npx cdk deploy VpnUs        # US only
```

Deployment takes ~2 minutes. On completion, CDK prints the stack outputs — you
don't need to note them down; `connect.sh` reads them automatically via the AWS
CLI.

### 3. Set up GitHub Actions (optional, for automated deploys)

Create an OIDC role in your AWS account that GitHub can assume:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REPO="sailorgeoffrey/vpn"

# Create the OIDC provider (skip if it already exists)
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# Create the role
aws iam create-role \
  --role-name github-actions \
  --assume-role-policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": {\"Federated\": \"arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com\"},
      \"Action\": \"sts:AssumeRoleWithWebIdentity\",
      \"Condition\": {
        \"StringEquals\": {\"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\"},
        \"StringLike\":   {\"token.actions.githubusercontent.com:sub\": \"repo:${REPO}:*\"}
      }
    }]
  }"

aws iam attach-role-policy \
  --role-name github-actions \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Then add your account ID as a GitHub Actions variable:

| Variable | Value |
|---|---|
| `AWS_ACCOUNT_ID` | Your 12-digit AWS account ID |

The workflow (`deploy.yml`) triggers automatically on pushes to `main`. You can
also trigger it manually from the Actions tab and choose which stack to deploy.

## Connecting

Copy `connect.sh` to your Tart VM (or clone the repo there), then:

```bash
# Connect through EU (default)
./connect.sh up

# Connect through US
./connect.sh up us

# Disconnect and terminate the instance
./connect.sh down
./connect.sh down us
```

The script prints the instance ID and public IP when the tunnel comes up, and
confirms termination on the way down.

## Cost

| Resource | Cost |
|---|---|
| EC2 t4g.nano | ~$0.0042/hr while running (on-demand) |
| KMS keys | ~$1.00/month per region |
| SSM SecureString parameters | Free (under the free-tier limit) |
| Data transfer out | $0.09/GB (EU), $0.09/GB (US) |

A typical 1-hour session costs less than a cent in compute. The KMS keys are
the only persistent cost (~$2/month for both regions).

## Rotating keys

Bump the `Version` property in `lib/vpn-stack.ts` and redeploy:

```typescript
new cdk.CustomResource(this, 'ClientKeypair', {
  serviceToken: provider.serviceToken,
  properties: {
    Version: '2',   // increment to force new keypair generation
  },
});
```

The Lambda will generate a new client keypair and overwrite the old one in SSM.
The EC2 instance generates a fresh server keypair on each launch anyway, so no
action is needed there.

## Project structure

```
├── bin/vpn.ts                    CDK app entry point (two stacks)
├── lib/vpn-stack.ts              Shared stack construct
├── lambda/generate_keypair.py    Custom Resource Lambda
├── connect.sh                    Connect/disconnect script for the Tart VM
├── .github/workflows/deploy.yml  GitHub Actions CI/CD
├── cdk.json
├── tsconfig.json
└── package.json
```
