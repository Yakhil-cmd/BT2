### Title
WalletConnect `chia_signMessageById` Confirmation Dialog Omits Entity Type, Enabling Signing-Context Confusion — (File: `packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

The WalletConnect confirmation dialog for `chia_signMessageById` displays the `id` parameter with the generic label **"Id"** and no entity-type context. Because `sign_message_by_id` accepts both NFT IDs and DID IDs, a malicious dApp can pass a DID ID while the user believes they are authorizing a signature under their NFT identity (or vice versa). The user approves based on incomplete context, and the resulting signature is cryptographically valid under the wrong identity.

---

### Finding Description

`sign_message_by_id` in `WalletService.ts` accepts a single `id` field that the backend resolves to either an NFT or a DID, then signs accordingly:

```ts
async signMessageById(args: { id: string; message: string }) {
  return this.command<{ pubkey: string; signature: string; latestCoinId: string }>(
    'sign_message_by_id', args
  );
}
``` [1](#0-0) 

The WalletConnect command registry entry for `chia_wallet.sign_message_by_id` defines the confirmation dialog parameters as:

```ts
params: [
  { name: 'id',      label: () => i18n._({ id: 'Id' }),      type: 'string' },
  { name: 'message', label: () => i18n._({ id: 'Message' }), type: 'string' },
  { name: 'is_hex',  ..., isOptional: true },
],
``` [2](#0-1) 

The label is simply **"Id"** — no indication of whether the ID refers to an NFT or a DID. The backend error-handling in `SignMessage.tsx` confirms that both NFT IDs and DID IDs are valid inputs to this single endpoint:

```ts
const missingNFTMatch = error.message.match(/^NFT for (.*) doesn't exist/);
const missingDIDMatch = error.message.match(/^DID for (.*) doesn't exist/);
``` [3](#0-2) 

The `SignMessageEntityType` enum makes clear that NFT and DID are distinct signing contexts with different trust semantics: [4](#0-3) 

However, none of this entity-type context is surfaced in the WalletConnect confirmation dialog. The user sees only the raw ID string and the message body.

---

### Impact Explanation

A malicious dApp that has been granted `chia_signMessageById` permission can:

1. Pass a **DID ID** (`did:chia:...`) while crafting a `message` that makes the user believe they are signing in the context of their NFT identity.
2. The user sees `Id: did:chia:xyz...` labeled only as "Id" — no "DID" label, no entity-type indicator.
3. The user approves.
4. The backend produces a cryptographically valid signature under the **DID** key.
5. The attacker uses this signature to prove DID ownership or authenticate as the DID holder in an external protocol — an identity the user did not intend to expose or authorize.

The inverse also applies: a DID-owning user can be tricked into signing with an NFT identity they did not intend to use.

This is a **signing-context confusion** issue: the user approves a signing operation without knowing the full context (entity type), and the resulting signature is valid under the wrong identity. This falls under the High impact criterion: *"WalletConnect state that causes a user to approve or sign the wrong asset, identity, amount, destination, or status."*

---

### Likelihood Explanation

- The attacker must be a dApp that the user has already connected via WalletConnect and granted `chia_signMessageById` permission — a realistic scenario for any dApp that requests signing capability.
- The user must own both an NFT and a DID (common for active Chia users).
- The attack requires only crafting a misleading `message` string alongside the substituted `id` — no cryptographic capability or key access needed.
- The `did:chia:` prefix is distinctive but not prominently labeled in the dialog; users focused on the message content are likely to overlook it.

---

### Recommendation

The confirmation dialog for `chia_signMessageById` should resolve and display the entity type (NFT or DID) alongside the raw ID, so the user can make an informed decision. Concretely:

- Add a `type` display field to the WalletConnect command params (e.g., "Entity Type: NFT" or "Entity Type: DID"), resolved from the ID prefix before showing the dialog.
- Alternatively, use separate WalletConnect commands for NFT signing and DID signing, mirroring the GUI's own `SignMessageEntityType` distinction. [5](#0-4) 

---

### Proof of Concept

1. User has NFT `nft1abc...` and DID `did:chia:xyz...`.
2. Malicious dApp (already paired via WalletConnect with `chia_signMessageById` permission) sends:
   ```json
   { "id": "did:chia:xyz...", "message": "I authorize transfer of NFT nft1abc..." }
   ```
3. GUI shows confirmation dialog:
   - **Id:** `did:chia:xyz...`
   - **Message:** `I authorize transfer of NFT nft1abc...`
   - No "DID" label; no entity-type indicator.
4. User reads the message, believes they are signing in the context of their NFT, and clicks **Sign**.
5. Backend calls `sign_message_by_id` with the DID ID; produces a signature under the DID key.
6. Attacker receives a valid DID-identity signature the user never intended to produce, usable to prove DID ownership in any protocol that accepts Chia DID signatures. [2](#0-1) [1](#0-0)

### Citations

**File:** packages/api/src/services/WalletService.ts (L409-415)
```typescript
  async signMessageById(args: { id: string; message: string }) {
    return this.command<{
      pubkey: string;
      signature: string;
      latestCoinId: string;
    }>('sign_message_by_id', args);
  }
```

**File:** packages/gui/src/electron/commands/Commands.ts (L400-420)
```typescript
  'chia_wallet.sign_message_by_id': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Sign Message' }),
    message: () => i18n._(/* i18n */ { id: 'Are you sure you want to sign this message?' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Sign' }),
    params: [
      { name: 'id', label: () => i18n._(/* i18n */ { id: 'Id' }), type: 'string' },
      { name: 'message', label: () => i18n._(/* i18n */ { id: 'Message' }), type: 'string' },
      {
        name: 'is_hex',
        label: () => i18n._(/* i18n */ { id: 'Message Is Hex Encoded String' }),
        type: 'bool',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_signMessageById',
        title: () => i18n._(/* i18n */ { id: 'Sign Message by Id' }),
      },
    ],
  },
```

**File:** packages/gui/src/components/signVerify/SignMessage.tsx (L104-106)
```typescript
      const missingNFTMatch = error.message.match(/^NFT for (.*) doesn't exist/);
      const missingDIDMatch = error.message.match(/^DID for (.*) doesn't exist/);

```

**File:** packages/gui/src/components/signVerify/SignMessageEntities.ts (L1-26)
```typescript
export enum SignMessageEntityType {
  WalletAddress = 'WALLET_ADDRESS',
  NFT = 'NFT',
  DID = 'DID',
}

export interface SignMessageWalletAddressEntity {
  type: SignMessageEntityType.WalletAddress;
  address: string;
}

export interface SignMessageNFTEntity {
  type: SignMessageEntityType.NFT;
  nftId: string;
  address: string;
}

export interface SignMessageDIDEntity {
  type: SignMessageEntityType.DID;
  didId: string;
  address: string;
}

export type SignMessageEntity = SignMessageWalletAddressEntity | SignMessageNFTEntity | SignMessageDIDEntity;


```
