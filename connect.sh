#!/usr/bin/env bash
# connect.sh – start or stop the WireGuard VPN through your personal AWS endpoint.
#
# Usage:
#   ./connect.sh up   [eu|us]    # default: eu
#   ./connect.sh down [eu|us]
#
# Prerequisites (on the Tart VM):
#   - wireguard-tools  (apt-get install wireguard-tools  or  brew install wireguard-tools)
#   - AWS CLI v2       (configured with a profile that has ec2:RunInstances,
#                       ec2:TerminateInstances, ssm:GetParameter, kms:Decrypt)
#   - jq
#
# The script reads CDK stack outputs to discover the Launch Template, subnet,
# security group, and SSM parameter paths – so you only need to run `cdk deploy`
# once; after that just run this script.

set -euo pipefail

COMMAND="${1:-up}"
REGION_ALIAS="${2:-eu}"

case "$REGION_ALIAS" in
  eu) AWS_REGION="eu-central-1"; STACK_NAME="VpnEu" ;;
  us) AWS_REGION="us-east-1";    STACK_NAME="VpnUs"  ;;
  *)  echo "Unknown region alias: $REGION_ALIAS (use 'eu' or 'us')"; exit 1 ;;
esac

WG_IFACE="wg0"
VPN_CONF="/tmp/wireguard-${REGION_ALIAS}.conf"
INSTANCE_ID_FILE="/tmp/wireguard-${REGION_ALIAS}-instance-id"

# ── Helper: fetch a CloudFormation stack output ───────────────────────────────
cfn_output() {
  local key="$1"
  aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='${key}'].OutputValue" \
    --output text
}

# ── Helper: get an SSM SecureString ──────────────────────────────────────────
ssm_get() {
  aws ssm get-parameter \
    --name "$1" \
    --region "$AWS_REGION" \
    --with-decryption \
    --query Parameter.Value \
    --output text
}

# ─────────────────────────────────────────────────────────────────────────────
up() {
  echo "[vpn] Starting WireGuard instance in ${AWS_REGION}..."

  LT_ID=$(cfn_output "LaunchTemplateId")
  SUBNET_ID=$(cfn_output "SubnetId")
  SG_ID=$(cfn_output "SecurityGroupId")

  # Launch the instance (no EIP; IP is dynamic – we learn it after boot)
  INSTANCE_ID=$(aws ec2 run-instances \
    --region "$AWS_REGION" \
    --launch-template "LaunchTemplateId=${LT_ID}" \
    --network-interfaces "DeviceIndex=0,SubnetId=${SUBNET_ID},AssociatePublicIpAddress=true,Groups=${SG_ID}" \
    --query 'Instances[0].InstanceId' \
    --output text)

  echo "[vpn] Instance launched: $INSTANCE_ID"
  echo "$INSTANCE_ID" > "$INSTANCE_ID_FILE"

  echo "[vpn] Waiting for instance to be running..."
  aws ec2 wait instance-running \
    --instance-ids "$INSTANCE_ID" \
    --region "$AWS_REGION"

  PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$AWS_REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)

  echo "[vpn] Public IP: $PUBLIC_IP"

  # Wait for user-data to push server public key to SSM (up to 3 minutes)
  SERVER_PUB_PARAM=$(cfn_output "ServerPublicKeyParam")
  echo "[vpn] Waiting for server to store its public key in SSM..."
  for i in $(seq 1 36); do
    if SERVER_PUBLIC=$(ssm_get "$SERVER_PUB_PARAM" 2>/dev/null); then
      break
    fi
    sleep 5
    echo "[vpn]   ... still waiting ($((i * 5))s)"
  done

  if [[ -z "${SERVER_PUBLIC:-}" ]]; then
    echo "[vpn] ERROR: timed out waiting for server public key"
    down
    exit 1
  fi

  # Fetch client private key from SSM
  CLIENT_PRIV_PARAM=$(cfn_output "ClientPrivateKeyParam")
  CLIENT_PRIVATE=$(ssm_get "$CLIENT_PRIV_PARAM")

  # Write wg0.conf locally
  cat > "$VPN_CONF" << EOF
[Interface]
Address = 10.0.0.2/24
PrivateKey = ${CLIENT_PRIVATE}
DNS = 1.1.1.1

[Peer]
PublicKey = ${SERVER_PUBLIC}
Endpoint = ${PUBLIC_IP}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

  chmod 600 "$VPN_CONF"

  echo "[vpn] Bringing up WireGuard tunnel..."
  sudo wg-quick up "$VPN_CONF"

  echo ""
  echo "[vpn] ✅ Connected. All traffic is now routed through ${AWS_REGION}."
  echo "[vpn]    Instance: $INSTANCE_ID   IP: $PUBLIC_IP"
  echo "[vpn]    Run './connect.sh down ${REGION_ALIAS}' to stop."
}

# ─────────────────────────────────────────────────────────────────────────────
down() {
  echo "[vpn] Tearing down WireGuard VPN (${REGION_ALIAS})..."

  # Bring down the tunnel if it's up
  if sudo wg show "$WG_IFACE" &>/dev/null 2>&1; then
    sudo wg-quick down "$VPN_CONF" || true
  elif [[ -f "$VPN_CONF" ]]; then
    sudo wg-quick down "$VPN_CONF" || true
  fi

  # Terminate the EC2 instance
  if [[ -f "$INSTANCE_ID_FILE" ]]; then
    INSTANCE_ID=$(cat "$INSTANCE_ID_FILE")
    echo "[vpn] Terminating instance $INSTANCE_ID..."
    aws ec2 terminate-instances \
      --instance-ids "$INSTANCE_ID" \
      --region "$AWS_REGION" \
      --output text > /dev/null
    rm "$INSTANCE_ID_FILE"
  else
    echo "[vpn] No instance ID file found – nothing to terminate."
  fi

  # Clean up the local config
  rm -f "$VPN_CONF"

  echo "[vpn] ✅ Disconnected and instance terminated."
}

# ─────────────────────────────────────────────────────────────────────────────
case "$COMMAND" in
  up)   up   ;;
  down) down ;;
  *)    echo "Usage: $0 [up|down] [eu|us]"; exit 1 ;;
esac
