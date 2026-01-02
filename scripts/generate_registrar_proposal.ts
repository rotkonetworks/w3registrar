#!/usr/bin/env -S npx ts-node
/**
 * Generate XCM call data for adding a registrar on Kusama People Chain
 *
 * Usage:
 *   npx ts-node scripts/generate_registrar_proposal.ts <registrar_account>
 *
 * Example:
 *   npx ts-node scripts/generate_registrar_proposal.ts HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F
 */

import { ApiPromise, WsProvider } from "@polkadot/api";
import { blake2AsHex } from "@polkadot/util-crypto";

const KUSAMA_RPC = "wss://kusama-rpc.polkadot.io";
const PEOPLE_KUSAMA_RPC = "wss://people-kusama.dotters.network";
const PEOPLE_PARA_ID = 1004;

// Weight for add_registrar call (conservative estimate)
const TRANSACT_WEIGHT = {
  refTime: 1_000_000_000n,
  proofSize: 100_000n,
};

async function main() {
  const registrarAccount = process.argv[2];

  if (!registrarAccount) {
    console.error("Usage: npx ts-node generate_registrar_proposal.ts <registrar_account>");
    console.error("Example: npx ts-node generate_registrar_proposal.ts HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F");
    process.exit(1);
  }

  console.log("Connecting to chains...\n");

  // Connect to People Chain to get the inner call encoding
  const peopleProvider = new WsProvider(PEOPLE_KUSAMA_RPC);
  const peopleApi = await ApiPromise.create({ provider: peopleProvider });

  // Connect to Kusama relay chain for the XCM wrapper
  const kusamaProvider = new WsProvider(KUSAMA_RPC);
  const kusamaApi = await ApiPromise.create({ provider: kusamaProvider });

  console.log(`Registrar account: ${registrarAccount}\n`);

  // Step 1: Encode the inner call (Identity.add_registrar)
  const addRegistrarCall = peopleApi.tx.identity.addRegistrar(registrarAccount);
  const encodedInnerCall = addRegistrarCall.method.toHex();

  console.log("=== Inner Call (People Chain) ===");
  console.log(`Call: identity.addRegistrar(${registrarAccount})`);
  console.log(`Encoded: ${encodedInnerCall}\n`);

  // Step 2: Build XCM message
  const xcmMessage = {
    V4: [
      {
        UnpaidExecution: {
          weightLimit: "Unlimited",
          checkOrigin: null,
        },
      },
      {
        Transact: {
          originKind: "Superuser",
          requireWeightAtMost: {
            refTime: TRANSACT_WEIGHT.refTime.toString(),
            proofSize: TRANSACT_WEIGHT.proofSize.toString(),
          },
          call: {
            encoded: encodedInnerCall,
          },
        },
      },
    ],
  };

  // Step 3: Build destination
  const destination = {
    V4: {
      parents: 0,
      interior: {
        X1: [{ Parachain: PEOPLE_PARA_ID }],
      },
    },
  };

  // Step 4: Create the full XCM send call
  const xcmSendCall = kusamaApi.tx.xcmPallet.send(destination, xcmMessage);
  const encodedXcmCall = xcmSendCall.method.toHex();

  console.log("=== XCM Call (Kusama Relay) ===");
  console.log(`Call: xcmPallet.send`);
  console.log(`Destination: Parachain ${PEOPLE_PARA_ID} (People Chain)`);
  console.log(`Encoded: ${encodedXcmCall}\n`);

  // Step 5: Calculate preimage hash
  const preimageHash = blake2AsHex(xcmSendCall.method.toU8a(), 256);

  console.log("=== Preimage ===");
  console.log(`Hash: ${preimageHash}`);
  console.log(`Length: ${xcmSendCall.method.toU8a().length} bytes\n`);

  // Step 6: Output instructions
  console.log("=== Next Steps ===");
  console.log("1. Go to https://polkadot.js.org/apps/?rpc=wss://kusama-rpc.polkadot.io#/preimages");
  console.log("2. Click 'Add preimage'");
  console.log("3. Use the following call:");
  console.log(`   - Section: xcmPallet`);
  console.log(`   - Method: send`);
  console.log(`   - dest: V4 { parents: 0, interior: X1(Parachain(${PEOPLE_PARA_ID})) }`);
  console.log(`   - message: (copy XCM structure above)`);
  console.log("4. Submit preimage transaction");
  console.log("5. Go to Referenda and submit proposal with:");
  console.log(`   - Origin: Root`);
  console.log(`   - Preimage hash: ${preimageHash}`);
  console.log("\nOr use the encoded call data directly:");
  console.log(encodedXcmCall);

  await peopleApi.disconnect();
  await kusamaApi.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
