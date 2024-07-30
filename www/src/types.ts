// types.ts
export interface IdentityField {
  id: string;
  placeholder: string;
  type: string;
}

export interface Challenge {
  id: string;
  value: string;
  verified: boolean;
}

export interface Instruction {
  id: number;
  text: string;
}

export interface AppData {
  timer: string;
  user: string;
  identityFields: IdentityField[];
  challenges: Challenge[];
  instructions: Instruction[];
}
