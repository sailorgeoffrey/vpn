import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cr from 'aws-cdk-lib/custom-resources';
import {Construct} from 'constructs';
import * as path from 'path';

export interface VpnStackProps extends cdk.StackProps {
    /**
     * A name suffix to distinguish regional stacks, e.g. "eu" or "us".
     */
    regionAlias: string;
}

export class VpnStack extends cdk.Stack {
    /** The Launch Template to use when starting the WireGuard instance. */
    public readonly launchTemplateId: cdk.CfnOutput;

    /** SSM path where the connect script can find the client private key. */
    public readonly clientPrivateKeyParam: cdk.CfnOutput;

    /** SSM path where the connect script can find the server public key. */
    public readonly serverPublicKeyParam: cdk.CfnOutput;

    constructor(scope: Construct, id: string, props: VpnStackProps) {
        super(scope, id, props);

        // ── KMS key ──────────────────────────────────────────────────────────────
        const key = new kms.Key(this, 'WireguardKey', {
            alias: `wireguard-vpn-${props.regionAlias}`,
            description: 'Encrypts WireGuard keypairs stored in SSM Parameter Store',
            enableKeyRotation: true,
            removalPolicy: cdk.RemovalPolicy.RETAIN,
        });

        // ── VPC: single public subnet, no NAT gateways ───────────────────────────
        const vpc = new ec2.Vpc(this, 'Vpc', {
            maxAzs: 1,
            natGateways: 0,
            subnetConfiguration: [{
                name: 'public',
                subnetType: ec2.SubnetType.PUBLIC,
                cidrMask: 28,
            }],
        });

        // ── Security group ────────────────────────────────────────────────────────
        const sg = new ec2.SecurityGroup(this, 'WireguardSg', {
            vpc,
            description: 'WireGuard VPN - allow UDP 51820 inbound',
            allowAllOutbound: true,
        });
        sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udp(51820), 'WireGuard');

        // ── IAM instance role ─────────────────────────────────────────────────────
        const instanceRole = new iam.Role(this, 'WireguardInstanceRole', {
            assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
            ],
        });
        // Allow the instance to write its server keypair to SSM
        instanceRole.addToPolicy(new iam.PolicyStatement({
            actions: ['ssm:PutParameter', 'ssm:GetParameter'],
            resources: [
                `arn:${this.partition}:ssm:${this.region}:${this.account}:parameter/wireguard/${props.regionAlias}/*`,
            ],
        }));
        instanceRole.addToPolicy(new iam.PolicyStatement({
            actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
            resources: [key.keyArn],
        }));

        // ── User data – installs WireGuard & generates server keypair on first boot
        const userData = ec2.UserData.forLinux();
        userData.addCommands(
            'set -e',
            'apt-get update -y',
            'apt-get install -y wireguard awscli jq',

            // Generate server keypair only if not already stored
            `REGION="${this.region}"`,
            `ALIAS="${props.regionAlias}"`,
            'PRIV_PARAM="/wireguard/$ALIAS/server/private-key"',
            'PUB_PARAM="/wireguard/$ALIAS/server/public-key"',

            // Check if server private key already exists in SSM
            `if ! aws ssm get-parameter --name "$PRIV_PARAM" --region "$REGION" --with-decryption > /dev/null 2>&1; then`,
            '  SERVER_PRIVATE=$(wg genkey)',
            '  SERVER_PUBLIC=$(echo "$SERVER_PRIVATE" | wg pubkey)',
            '  aws ssm put-parameter --name "$PRIV_PARAM" --value "$SERVER_PRIVATE" --type "SecureString" --key-id "alias/wireguard-vpn-$ALIAS" --region "$REGION" --overwrite',
            '  aws ssm put-parameter --name "$PUB_PARAM"  --value "$SERVER_PUBLIC"  --type "SecureString" --key-id "alias/wireguard-vpn-$ALIAS" --region "$REGION" --overwrite',
            'fi',

            // Wait for the client public key to appear in SSM (placed there by the Lambda custom resource)
            `until aws ssm get-parameter --name "/wireguard/$ALIAS/client/public-key" --region "$REGION" --with-decryption > /dev/null 2>&1; do sleep 5; done`,
            `CLIENT_PUBLIC=$(aws ssm get-parameter --name "/wireguard/$ALIAS/client/public-key" --region "$REGION" --with-decryption --query Parameter.Value --output text)`,
            `SERVER_PRIVATE=$(aws ssm get-parameter --name "$PRIV_PARAM" --region "$REGION" --with-decryption --query Parameter.Value --output text)`,

            // Write wg0.conf
            'cat > /etc/wireguard/wg0.conf << EOF',
            '[Interface]',
            'Address = 10.0.0.1/24',
            'ListenPort = 51820',
            'PrivateKey = $SERVER_PRIVATE',
            '',
            '# Enable IP forwarding and NAT so VPN clients can reach the internet',
            'PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip route | grep default | awk \'{print $5}\') -j MASQUERADE; sysctl -w net.ipv4.ip_forward=1',
            'PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip route | grep default | awk \'{print $5}\') -j MASQUERADE',
            '',
            '[Peer]',
            'PublicKey = $CLIENT_PUBLIC',
            'AllowedIPs = 10.0.0.2/32',
            'EOF',

            'systemctl enable wg-quick@wg0',
            'systemctl start  wg-quick@wg0 || true',
        );

        // ── Launch Template ───────────────────────────────────────────────────────
        // Use ARM (Graviton) t4g.nano – cheapest instance with good network throughput
        const launchTemplate = new ec2.LaunchTemplate(this, 'WireguardTemplate', {
            launchTemplateName: `wireguard-vpn-${props.regionAlias}`,
            instanceType: ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.NANO),
            machineImage: ec2.MachineImage.fromSsmParameter(
                '/aws/service/canonical/ubuntu/server/22.04/stable/current/arm64/hvm/ebs-gp2/ami-id',
            ),
            securityGroup: sg,
            role: instanceRole,
            userData,
            requireImdsv2: true,
            // No EBS encryption needed – keypairs live in SSM, not on disk long-term
            blockDevices: [{
                deviceName: '/dev/sda1',
                volume: ec2.BlockDeviceVolume.ebs(8, {deleteOnTermination: true}),
            }],
        });

        // ── Lambda: generate client keypair (runs once at deploy time) ───────────
        const keypairLambda = new lambda.Function(this, 'ClientKeypairFn', {
            runtime: lambda.Runtime.PYTHON_3_12,
            handler: 'generate_keypair.handler',
            code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
            timeout: cdk.Duration.minutes(2),
            environment: {
                REGION: this.region,
                REGION_ALIAS: props.regionAlias,
                KMS_KEY_ARN: key.keyArn,
            },
        });

        keypairLambda.addToRolePolicy(new iam.PolicyStatement({
            actions: ['ssm:PutParameter', 'ssm:GetParameter', 'ssm:DeleteParameter'],
            resources: [
                `arn:${this.partition}:ssm:${this.region}:${this.account}:parameter/wireguard/${props.regionAlias}/*`,
            ],
        }));
        keypairLambda.addToRolePolicy(new iam.PolicyStatement({
            actions: ['kms:GenerateDataKey', 'kms:Decrypt', 'kms:CreateGrant'],
            resources: [key.keyArn],
        }));

        // Grant the deploying principal (human or CI) read access to client private key
        key.addToResourcePolicy(new iam.PolicyStatement({
            principals: [new iam.AccountRootPrincipal()],
            actions: ['kms:Decrypt', 'kms:DescribeKey'],
            resources: ['*'],
        }));

        // ── Custom Resource: trigger the Lambda at deploy time ───────────────────
        const provider = new cr.Provider(this, 'KeypairProvider', {
            onEventHandler: keypairLambda,
        });

        new cdk.CustomResource(this, 'ClientKeypair', {
            serviceToken: provider.serviceToken,
            properties: {
                // Bump this to force key rotation
                Version: '1',
            },
        });

        // ── Outputs ───────────────────────────────────────────────────────────────
        this.launchTemplateId = new cdk.CfnOutput(this, 'LaunchTemplateId', {
            value: launchTemplate.launchTemplateId!,
            description: 'Pass to connect script: aws ec2 run-instances --launch-template LaunchTemplateId=...',
        });

        this.clientPrivateKeyParam = new cdk.CfnOutput(this, 'ClientPrivateKeyParam', {
            value: `/wireguard/${props.regionAlias}/client/private-key`,
            description: 'SSM path for client WireGuard private key (KMS-encrypted)',
        });

        this.serverPublicKeyParam = new cdk.CfnOutput(this, 'ServerPublicKeyParam', {
            value: `/wireguard/${props.regionAlias}/server/public-key`,
            description: 'SSM path for server WireGuard public key (KMS-encrypted)',
        });

        new cdk.CfnOutput(this, 'SubnetId', {
            value: vpc.publicSubnets[0].subnetId,
            description: 'Subnet to use when launching the WireGuard instance',
        });

        new cdk.CfnOutput(this, 'SecurityGroupId', {
            value: sg.securityGroupId,
        });
    }
}
