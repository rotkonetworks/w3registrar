#!/usr/bin/env -S npx ts-node
/**
 * Test add_registrar on local zombienet
 *
 * Usage:
 *   npx ts-node scripts/test_local_registrar.ts
 */

import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { cryptoWaitReady } from "@polkadot/util-crypto";

const RELAY_RPC = process.env.RELAY_RPC || "ws://127.0.0.1:44691";
const PEOPLE_RPC = process.env.PEOPLE_RPC || "ws://127.0.0.1:33627";

// Weight for add_registrar call (conservative estimate)
const TRANSACT_WEIGHT = {
  refTime: 500_000_000,
  proofSize: 50_000,
};

async function main() {
  await cryptoWaitReady();

  console.log("Connecting to chains...");
  console.log(`  Relay: ${RELAY_RPC}`);
  console.log(`  People: ${PEOPLE_RPC}\n`);

  const relayProvider = new WsProvider(RELAY_RPC);
  const relayApi = await ApiPromise.create({ provider: relayProvider });

  const peopleProvider = new WsProvider(PEOPLE_RPC);
  const peopleApi = await ApiPromise.create({ provider: peopleProvider });

  // Setup keyring with Alice (has sudo on local)
  const keyring = new Keyring({ type: "sr25519" });
  const alice = keyring.addFromUri("//Alice");
  const bob = keyring.addFromUri("//Bob");

  console.log(`Alice: ${alice.address}`);
  console.log(`Bob (registrar): ${bob.address}\n`);

  // Check current registrars
  console.log("=== Current Registrars ===");
  const registrars = await peopleApi.query.identity.registrars();
  console.log(`Registrars: ${JSON.stringify(registrars.toHuman(), null, 2)}\n`);

  // Step 1: Use sudo on people chain directly (local dev mode)
  // In production, this would be an XCM from relay chain governance
  console.log("=== Step 1: Add Registrar via sudo ===");

  const addRegistrarCall = peopleApi.tx.identity.addRegistrar(bob.address);
  console.log(`Inner call: ${addRegistrarCall.method.toHex()}\n`);

  // Check if people chain has sudo
  const hasSudo = peopleApi.tx.sudo !== undefined;

  if (hasSudo) {
    console.log("Using sudo.sudo on People Chain...");
    const sudoCall = peopleApi.tx.sudo.sudo(addRegistrarCall);

    try {
      const result = await new Promise((resolve, reject) => {
        sudoCall.signAndSend(alice, ({ status, events, dispatchError }) => {
          console.log(`Status: ${status.type}`);

          if (status.isInBlock || status.isFinalized) {
            if (dispatchError) {
              if (dispatchError.isModule) {
                const decoded = peopleApi.registry.findMetaError(dispatchError.asModule);
                reject(new Error(`${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`));
              } else {
                reject(new Error(dispatchError.toString()));
              }
            } else {
              // Check for sudo success/failure
              events.forEach(({ event }) => {
                if (event.section === "sudo") {
                  console.log(`Sudo event: ${event.method} - ${event.data.toString()}`);
                }
              });
              resolve(status.asInBlock.toString());
            }
          }
        });
      });
      console.log(`Included in block: ${result}\n`);
    } catch (err) {
      console.error(`Error: ${err}\n`);
    }
  } else {
    console.log("No sudo pallet on People Chain, trying XCM from relay...\n");

    // Build XCM message
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
            requireWeightAtMost: TRANSACT_WEIGHT,
            call: {
              encoded: addRegistrarCall.method.toHex(),
            },
          },
        },
      ],
    };

    const destination = {
      V4: {
        parents: 0,
        interior: {
          X1: [{ Parachain: 1004 }],
        },
      },
    };

    // On local dev, relay chain has sudo too
    const xcmSend = relayApi.tx.xcmPallet.send(destination, xcmMessage);
    const sudoXcm = relayApi.tx.sudo.sudo(xcmSend);

    console.log("Sending XCM via sudo on relay chain...");
    try {
      const result = await new Promise((resolve, reject) => {
        sudoXcm.signAndSend(alice, ({ status, dispatchError }) => {
          console.log(`Status: ${status.type}`);
          if (status.isFinalized) {
            if (dispatchError) {
              reject(dispatchError);
            } else {
              resolve(status.asFinalized.toString());
            }
          }
        });
      });
      console.log(`Finalized: ${result}\n`);
    } catch (err) {
      console.error(`XCM Error: ${err}\n`);
    }
  }

  // Wait a bit for parachain to process
  console.log("Waiting for parachain to process...");
  await new Promise((r) => setTimeout(r, 12000));

  // Verify registrar was added
  console.log("\n=== Verifying Registrar ===");
  const newRegistrars = await peopleApi.query.identity.registrars();
  console.log(`Registrars: ${JSON.stringify(newRegistrars.toHuman(), null, 2)}\n`);

  const registrarArray = newRegistrars.toJSON() as any[];
  const registrarCount = registrarArray ? registrarArray.length : 0;
  if (registrarCount > 0) {
    console.log(`✓ Registrar added! Index: ${registrarCount - 1}`);

    // Step 2: Set registrar fields
    console.log("\n=== Step 2: Set Registrar Fields ===");
    const fields = 665; // Display + Matrix + Email + Twitter + Discord
    const setFieldsCall = peopleApi.tx.identity.setFields(registrarCount - 1, fields);

    try {
      await new Promise((resolve, reject) => {
        setFieldsCall.signAndSend(bob, ({ status, dispatchError }) => {
          console.log(`Status: ${status.type}`);
          if (status.isInBlock) {
            if (dispatchError) {
              reject(dispatchError);
            } else {
              resolve(status.asInBlock.toString());
            }
          }
        });
      });
      console.log(`✓ Fields set to ${fields}\n`);
    } catch (err) {
      console.error(`Error setting fields: ${err}\n`);
    }

    // Step 3: Set registrar fee
    console.log("=== Step 3: Set Registrar Fee ===");
    const fee = 1_000_000_000_000n; // 1 unit
    const setFeeCall = peopleApi.tx.identity.setFee(registrarCount - 1, fee);

    try {
      await new Promise((resolve, reject) => {
        setFeeCall.signAndSend(bob, ({ status, dispatchError }) => {
          console.log(`Status: ${status.type}`);
          if (status.isInBlock) {
            if (dispatchError) {
              reject(dispatchError);
            } else {
              resolve(status.asInBlock.toString());
            }
          }
        });
      });
      console.log(`✓ Fee set to ${fee}\n`);
    } catch (err) {
      console.error(`Error setting fee: ${err}\n`);
    }

    // Final verification
    console.log("=== Final Registrar State ===");
    const finalRegistrars = await peopleApi.query.identity.registrars();
    console.log(JSON.stringify(finalRegistrars.toHuman(), null, 2));
  } else {
    console.log("✗ No registrar found - check the XCM execution");
  }

  await relayApi.disconnect();
  await peopleApi.disconnect();

  console.log("\nDone!");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
