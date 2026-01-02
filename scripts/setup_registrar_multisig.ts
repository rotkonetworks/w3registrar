#!/usr/bin/env -S npx ts-node
/**
 * Setup Registrar with Multisig-controlled Pure Proxy
 *
 * Architecture:
 *   3-of-5 Multisig (cold storage, owns everything)
 *       └── Pure Proxy (the registrar account submitted to governance)
 *               └── IdentityJudgement Proxy (hot wallet for w3registrar backend)
 *
 * Usage:
 *   npx ts-node setup_registrar_multisig.ts --network kusama \
 *     --signatories addr1,addr2,addr3,addr4,addr5 \
 *     --threshold 3 \
 *     --hot-wallet <hot_wallet_address>
 *
 * For local testing:
 *   npx ts-node setup_registrar_multisig.ts --network local \
 *     --signatories //Alice,//Bob,//Charlie,//Dave,//Eve \
 *     --threshold 3 \
 *     --hot-wallet //Ferdie
 */

import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { cryptoWaitReady, sortAddresses, encodeMultiAddress } from "@polkadot/util-crypto";
import type { KeyringPair } from "@polkadot/keyring/types";

interface Config {
  network: string;
  rpcEndpoint: string;
  signatories: string[];
  threshold: number;
  hotWallet: string;
  funder?: string; // Account to fund others (for testing)
}

const NETWORKS: Record<string, string> = {
  kusama: "wss://kusama-people-rpc.polkadot.io",
  polkadot: "wss://polkadot-people-rpc.polkadot.io",
  paseo: "wss://people-paseo.dotters.network",
  local: "ws://127.0.0.1:33627",
};

function parseArgs(): Config {
  const args = process.argv.slice(2);
  const config: Partial<Config> = {};

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--network":
        config.network = args[++i];
        break;
      case "--signatories":
        config.signatories = args[++i].split(",");
        break;
      case "--threshold":
        config.threshold = parseInt(args[++i]);
        break;
      case "--hot-wallet":
        config.hotWallet = args[++i];
        break;
      case "--funder":
        config.funder = args[++i];
        break;
      case "--rpc":
        config.rpcEndpoint = args[++i];
        break;
    }
  }

  if (!config.network) {
    console.error("Missing --network");
    process.exit(1);
  }
  if (!config.signatories || config.signatories.length < 2) {
    console.error("Missing or invalid --signatories (need at least 2)");
    process.exit(1);
  }
  if (!config.threshold || config.threshold < 2) {
    console.error("Missing or invalid --threshold (need at least 2)");
    process.exit(1);
  }
  if (config.threshold > config.signatories.length) {
    console.error("Threshold cannot exceed number of signatories");
    process.exit(1);
  }
  if (!config.hotWallet) {
    console.error("Missing --hot-wallet");
    process.exit(1);
  }

  config.rpcEndpoint = config.rpcEndpoint || NETWORKS[config.network];
  if (!config.rpcEndpoint) {
    console.error(`Unknown network: ${config.network}`);
    process.exit(1);
  }

  return config as Config;
}

async function main() {
  await cryptoWaitReady();

  const config = parseArgs();
  const keyring = new Keyring({ type: "sr25519" });

  console.log("=== Registrar Multisig Setup ===\n");
  console.log(`Network: ${config.network}`);
  console.log(`RPC: ${config.rpcEndpoint}`);
  console.log(`Threshold: ${config.threshold}-of-${config.signatories.length}`);
  console.log(`Signatories: ${config.signatories.join(", ")}`);
  console.log(`Hot Wallet: ${config.hotWallet}\n`);

  // Connect
  const provider = new WsProvider(config.rpcEndpoint);
  const api = await ApiPromise.create({ provider });

  // Resolve addresses (handle //Alice style URIs for testing)
  const signatoryPairs: KeyringPair[] = [];
  const signatoryAddresses: string[] = [];

  for (const sig of config.signatories) {
    if (sig.startsWith("//")) {
      const pair = keyring.addFromUri(sig);
      signatoryPairs.push(pair);
      signatoryAddresses.push(pair.address);
    } else {
      signatoryAddresses.push(sig);
    }
  }

  let hotWalletPair: KeyringPair | null = null;
  let hotWalletAddress: string;
  if (config.hotWallet.startsWith("//")) {
    hotWalletPair = keyring.addFromUri(config.hotWallet);
    hotWalletAddress = hotWalletPair.address;
  } else {
    hotWalletAddress = config.hotWallet;
  }

  // Sort addresses for deterministic multisig
  const sortedAddresses = sortAddresses(signatoryAddresses, api.registry.chainSS58);

  // Calculate multisig address
  const multisigAddress = encodeMultiAddress(sortedAddresses, config.threshold, api.registry.chainSS58);

  console.log("=== Computed Addresses ===");
  console.log(`Multisig Address: ${multisigAddress}`);
  console.log(`Hot Wallet: ${hotWalletAddress}\n`);

  // Check if we're in test mode (have signatory keypairs)
  const isTestMode = signatoryPairs.length >= config.threshold;

  if (isTestMode) {
    console.log("=== Test Mode: Executing transactions ===\n");

    // Fund accounts if funder provided
    if (config.funder) {
      const funderPair = keyring.addFromUri(config.funder);
      console.log(`Funder: ${funderPair.address}\n`);

      // Fund multisig
      console.log("Step 0: Funding accounts...");
      const fundAmount = api.consts.balances?.existentialDeposit
        ? (api.consts.balances.existentialDeposit as any).toBigInt() * 100n
        : 10_000_000_000_000n; // 10 units fallback

      const fundTxs = [
        api.tx.balances.transferKeepAlive(multisigAddress, fundAmount),
        api.tx.balances.transferKeepAlive(hotWalletAddress, fundAmount),
      ];

      for (const tx of fundTxs) {
        await signAndSend(tx, funderPair);
      }
      console.log("✓ Accounts funded\n");
    }

    // Step 1: Create Pure Proxy owned by multisig
    console.log("Step 1: Creating Pure Proxy from multisig...");

    // The call to create pure proxy
    const createPureCall = api.tx.proxy.createPure("Any", 0, 0);

    // Wrap in multisig
    const otherSignatories = sortedAddresses.filter(
      (addr) => addr !== signatoryPairs[0].address
    );

    // First signatory initiates
    const multisigCall = api.tx.multisig.asMulti(
      config.threshold,
      otherSignatories,
      null, // no prior timepoint
      createPureCall,
      { refTime: 1_000_000_000, proofSize: 100_000 }
    );

    let timepoint: { height: number; index: number } | null = null;

    // First signature
    const result1 = await signAndSendWithEvents(multisigCall, signatoryPairs[0], api);
    console.log(`  Signatory 1 (${signatoryPairs[0].address.slice(0, 8)}...) signed`);

    // Extract timepoint from MultisigApproval event
    for (const { event } of result1.events) {
      if (event.section === "multisig" && event.method === "MultisigApproval") {
        const data = event.data.toJSON() as any;
        timepoint = data.timepoint || { height: data[1], index: data[2] };
        break;
      }
    }

    if (!timepoint) {
      console.error("Failed to get timepoint from first signature");
      process.exit(1);
    }

    // Remaining signatures
    for (let i = 1; i < config.threshold; i++) {
      const signer = signatoryPairs[i];
      const others = sortedAddresses.filter((addr) => addr !== signer.address);

      const approveCall = api.tx.multisig.asMulti(
        config.threshold,
        others,
        timepoint,
        createPureCall,
        { refTime: 1_000_000_000, proofSize: 100_000 }
      );

      const result = await signAndSendWithEvents(approveCall, signer, api);
      console.log(`  Signatory ${i + 1} (${signer.address.slice(0, 8)}...) signed`);

      // Check for PureCreated event (final signature)
      for (const { event } of result.events) {
        if (event.section === "proxy" && event.method === "PureCreated") {
          const data = event.data.toJSON() as any;
          const pureProxyAddress = data.pure || data[0];
          console.log(`\n✓ Pure Proxy created: ${pureProxyAddress}\n`);

          // Step 2: Add hot wallet as IdentityJudgement proxy
          console.log("Step 2: Adding hot wallet as IdentityJudgement proxy...\n");

          // The proxy.addProxy call (from pure proxy, via multisig)
          const addProxyCall = api.tx.proxy.addProxy(hotWalletAddress, "IdentityJudgement", 0);

          // Wrap: multisig -> proxy.proxy (as pure) -> addProxy
          const proxyCall = api.tx.proxy.proxy(pureProxyAddress, null, addProxyCall);

          const multisigProxyCall = api.tx.multisig.asMulti(
            config.threshold,
            sortedAddresses.filter((addr) => addr !== signatoryPairs[0].address),
            null,
            proxyCall,
            { refTime: 1_000_000_000, proofSize: 100_000 }
          );

          const proxyResult1 = await signAndSendWithEvents(multisigProxyCall, signatoryPairs[0], api);
          console.log(`  Signatory 1 signed addProxy call`);

          // Get new timepoint
          let proxyTimepoint: { height: number; index: number } | null = null;
          for (const { event } of proxyResult1.events) {
            if (event.section === "multisig" && event.method === "MultisigApproval") {
              const d = event.data.toJSON() as any;
              proxyTimepoint = d.timepoint || { height: d[1], index: d[2] };
              break;
            }
          }

          // Remaining signatures for addProxy
          for (let j = 1; j < config.threshold; j++) {
            const proxySigner = signatoryPairs[j];
            const proxyOthers = sortedAddresses.filter((addr) => addr !== proxySigner.address);

            const approveProxyCall = api.tx.multisig.asMulti(
              config.threshold,
              proxyOthers,
              proxyTimepoint,
              proxyCall,
              { refTime: 1_000_000_000, proofSize: 100_000 }
            );

            await signAndSendWithEvents(approveProxyCall, proxySigner, api);
            console.log(`  Signatory ${j + 1} signed addProxy call`);
          }

          console.log(`\n✓ Hot wallet added as IdentityJudgement proxy\n`);

          // Summary
          console.log("=== Setup Complete ===");
          console.log(`Multisig (3-of-5):     ${multisigAddress}`);
          console.log(`Pure Proxy (registrar): ${pureProxyAddress}`);
          console.log(`Hot Wallet (backend):   ${hotWalletAddress}`);
          console.log(`\nThe Pure Proxy address should be submitted to governance as the registrar.`);
          console.log(`The hot wallet can call identity.provideJudgement on behalf of the pure proxy.`);

          await api.disconnect();
          return;
        }
      }
    }
  } else {
    // Production mode: just output the addresses and instructions
    console.log("=== Production Mode: Manual Steps Required ===\n");

    console.log("1. Fund the multisig address with some tokens for transaction fees:");
    console.log(`   ${multisigAddress}\n`);

    console.log("2. Create a Pure Proxy from the multisig:");
    console.log("   - All signatories go to: https://polkadot.js.org/apps/#/extrinsics");
    console.log("   - Select: proxy.createPure(proxyType: Any, delay: 0, index: 0)");
    console.log("   - Wrap in: multisig.asMulti(...)");
    console.log(`   - Threshold: ${config.threshold}`);
    console.log(`   - Other signatories: (exclude yourself from the list)\n`);

    console.log("3. After Pure Proxy is created, add hot wallet as proxy:");
    console.log("   - Call: proxy.proxy(pureProxyAddress, null, proxy.addProxy(...))");
    console.log(`   - Add: ${hotWalletAddress} as IdentityJudgement proxy`);
    console.log("   - Wrap in multisig.asMulti as before\n");

    console.log("4. Submit governance proposal to add Pure Proxy as registrar");
    console.log("   - Use: npx ts-node generate_registrar_proposal.ts <pure_proxy_address>\n");
  }

  await api.disconnect();
}

async function signAndSend(tx: any, signer: KeyringPair): Promise<string> {
  return new Promise((resolve, reject) => {
    tx.signAndSend(signer, ({ status, dispatchError }: any) => {
      if (status.isInBlock) {
        if (dispatchError) {
          reject(dispatchError);
        } else {
          resolve(status.asInBlock.toString());
        }
      }
    });
  });
}

async function signAndSendWithEvents(
  tx: any,
  signer: KeyringPair,
  api: ApiPromise
): Promise<{ blockHash: string; events: any[] }> {
  return new Promise((resolve, reject) => {
    tx.signAndSend(signer, ({ status, events, dispatchError }: any) => {
      if (status.isInBlock) {
        if (dispatchError) {
          if (dispatchError.isModule) {
            const decoded = api.registry.findMetaError(dispatchError.asModule);
            reject(new Error(`${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`));
          } else {
            reject(new Error(dispatchError.toString()));
          }
        } else {
          resolve({ blockHash: status.asInBlock.toString(), events });
        }
      }
    });
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
