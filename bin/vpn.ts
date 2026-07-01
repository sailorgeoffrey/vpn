#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { VpnStack } from '../lib/vpn-stack';

const app = new cdk.App();

// EU stack
new VpnStack(app, 'VpnEu', {
  regionAlias: 'eu',
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'eu-central-1' },
  description: 'WireGuard VPN – EU Central',
});

// US stack
new VpnStack(app, 'VpnUs', {
  regionAlias: 'us',
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'us-east-1' },
  description: 'WireGuard VPN – US East',
});
