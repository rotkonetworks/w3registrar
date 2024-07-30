// data.ts
import { AppData } from './types';

export const appData: AppData = {
  timer: "5h45m15s",
  user: "0xAlice",
  identityFields: [
    { id: "display_name", placeholder: "Display name: 0xAlice", type: "text" },
    { id: "matrix", placeholder: "Matrix: @alice:matrix.org", type: "text" },
    { id: "email", placeholder: "Email: alice@w3reg.org", type: "email" },
    { id: "discord", placeholder: "Discord: alice#123", type: "text" },
    { id: "twitter", placeholder: "Twitter: @alice", type: "text" }
  ],
  challenges: [
    { id: "display_name", value: "au30soiL2eiX", verified: true },
    { id: "matrix", value: "bai0ohdahX7i", verified: false },
    { id: "email", value: "Phahhohna7vi", verified: false },
    { id: "discord", value: "ieD0eng4xooc", verified: false },
    { id: "twitter", value: "shuoWoe9siid", verified: true }
  ],
  instructions: [
    { id: 1, text: "Submit identity to request judgement from registrar" },
    { id: 2, text: "Click to copy challenge and send it to us in DM" },
    { id: 3, text: "Once state of all the identities you want us to verify are green, we will provide you judgement" }
  ]
};
