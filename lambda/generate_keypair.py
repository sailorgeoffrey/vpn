"""
Custom Resource Lambda: generates a WireGuard client keypair and stores both
the private key (KMS-encrypted) and the public key in SSM Parameter Store.

WireGuard uses Curve25519.  Key generation only requires:
  1. 32 random bytes (private scalar)
  2. Clamping the scalar (per RFC 7748)
  3. Scalar-multiplying by the Curve25519 base point

We implement scalar multiplication in pure Python so there are zero dependencies
beyond the standard library.  The math is exactly what 'wg genkey' / 'wg pubkey'
produce.
"""
import os
import base64
import json
import boto3
import urllib.request

# ── Curve25519 scalar multiplication (pure Python, constant-time-ish) ────────
# Based on the reference implementation in RFC 7748.

P  = 2**255 - 19
A24 = 121665

def _clamp(k: bytearray) -> bytearray:
    k[0]  &= 248
    k[31] &= 127
    k[31] |= 64
    return k

def _mul(u: int, k: bytearray) -> int:
    """Multiply base point u by scalar k on Curve25519. Returns x-coordinate."""
    x_1 = u
    x_2 = 1; z_2 = 0
    x_3 = u; z_3 = 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k[t >> 3] >> (t & 7)) & 1
        swap ^= k_t
        # Conditional swap
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        A  = (x_2 + z_2) % P
        AA = (A * A) % P
        B  = (x_2 - z_2) % P
        BB = (B * B) % P
        E  = (AA - BB) % P
        C  = (x_3 + z_3) % P
        D  = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = pow(DA + CB, 2, P)
        z_3 = (x_1 * pow(DA - CB, 2, P)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + A24 * E)) % P
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    return (x_2 * pow(z_2, P - 2, P)) % P

def _generate_wireguard_keypair() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64) in WireGuard's base64 format."""
    priv_bytes = bytearray(os.urandom(32))
    _clamp(priv_bytes)
    base_point = 9
    pub_int = _mul(base_point, priv_bytes)
    pub_bytes = pub_int.to_bytes(32, 'little')
    return (
        base64.b64encode(bytes(priv_bytes)).decode(),
        base64.b64encode(pub_bytes).decode(),
    )

# ── CloudFormation custom resource response helper ────────────────────────────

def _send_response(event, context, status, data, reason=''):
    body = json.dumps({
        'Status': status,
        'Reason': reason,
        'PhysicalResourceId': event.get('PhysicalResourceId', 'ClientKeypair'),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data,
    })
    url = event['ResponseURL']
    req = urllib.request.Request(url, data=body.encode(), method='PUT')
    req.add_header('Content-Type', '')
    urllib.request.urlopen(req)


def handler(event, context):
    region    = os.environ['REGION']
    alias     = os.environ['REGION_ALIAS']
    kms_key_arn = os.environ['KMS_KEY_ARN']

    priv_param = f'/wireguard/{alias}/client/private-key'
    pub_param  = f'/wireguard/{alias}/client/public-key'

    ssm = boto3.client('ssm', region_name=region)

    try:
        request_type = event['RequestType']

        if request_type in ('Create', 'Update'):
            # Regenerate on Create, or on Update when Version property changes.
            should_generate = request_type == 'Create'
            if not should_generate:
                old_ver = (event.get('OldResourceProperties') or {}).get('Version', '')
                new_ver = (event.get('ResourceProperties') or {}).get('Version', '')
                should_generate = old_ver != new_ver

            if should_generate:
                private_key, public_key = _generate_wireguard_keypair()
                ssm.put_parameter(
                    Name=priv_param, Value=private_key,
                    Type='SecureString', KeyId=kms_key_arn, Overwrite=True,
                )
                ssm.put_parameter(
                    Name=pub_param, Value=public_key,
                    Type='SecureString', KeyId=kms_key_arn, Overwrite=True,
                )

            _send_response(event, context, 'SUCCESS', {}, 'Client keypair stored in SSM')

        elif request_type == 'Delete':
            for param in (priv_param, pub_param):
                try:
                    ssm.delete_parameter(Name=param)
                except ssm.exceptions.ParameterNotFound:
                    pass
            _send_response(event, context, 'SUCCESS', {}, 'Client keypair removed')

        else:
            _send_response(event, context, 'SUCCESS', {})

    except Exception as exc:
        _send_response(event, context, 'FAILED', {}, str(exc))
        raise
