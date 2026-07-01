#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { VpnStack } from '../lib/vpn-stack';

const app = new cdk.App();

// Resolve account from the environment so that Vpc.fromLookup works.
// CDK uses the AWS_ACCOUNT_ID env var or the currently-active AWS profile.
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  // region is overridden per-stack below, but CDK_DEFAULT_REGION is the fallback
};

// EU stack
new VpnStack(app, 'VpnEu', {
  regionAlias: 'eu',
  env: { ...env, region: 'eu-central-1' },
  description: 'WireGuard VPN – EU Central',
});

// US stack
new VpnStack(app, 'VpnUs', {
  regionAlias: 'us',
  env: { ...env, region: 'us-east-1' },
  description: 'WireGuard VPN – US East',
});
