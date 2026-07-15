### Title
Stale Cached Fingerprint Used in WalletConnect Authorization Allows Commands to Execute Against Wrong Wallet - (File: packages/gui/src/hooks/useWalletConnectCommand.tsx)

### Summary
`useWalletConnectCommand` performs its fingerprint authorization check using a stale React-hook-cached value of `currentFingerprint`. For all dapp commands that do not set `requiresSync: true` — including `chia_takeOffer`, `chia_signMessageByAddress`, `chia_signMessageById`, `chia_transferDID`, `chia_mintNFT`, `chia_pushTransactions`, and `chia_pushTx` — the guard never re-fetches the live fingerprint. A malicious dapp paired with wallet A can send a request in the race window after the user switches to wallet B, pass the stale check, and have the command execute against wallet B.

### Finding Description

`useWalletConnectCommand` obtains the currently logged-in fingerprint via the React hook `useGetLoggedInFingerprintQuery()`: [1](#0-0) 

This value is captured in the closure of `handleProcess`. The authorization guard at lines 38–46 compares this closure-captured, potentially stale value against `pair.fingerprint`: [2](#0-1) 

The code does re-fetch the fingerprint with `forceRefetch: true` — but **only** when `commandMetadata.requiresSync` is `true`: [3](#0-2) 

`getDappCommandMetadata` defaults `requiresSync` to `false` for any command that does not explicitly set it: [4](#0-3) 

A grep of `Commands.ts` shows only **four** commands carry `requiresSync: true` (`chia_sendTransaction`, `chia_spendCAT`, `chia_spendClawbackCoins`, and one other). The following high-impact dapp commands have **no** `requiresSync` and therefore never re-fetch the fingerprint:

- `chia_takeOffer` — offer acceptance (no `requiresSync`) [5](#0-4) 

- `chia_signMessageByAddress` / `chia_signMessageById` — wallet signing (no `requiresSync`) [6](#0-5) 

- `chia_transferDID` — DID transfer (no `requiresSync`) [7](#0-6) 

- `chia_mintNFT` / `chia_mintBulk` — NFT minting (no `requiresSync`) [8](#0-7) 

- `chia_pushTransactions` / `chia_pushTx` — raw transaction push (no `requiresSync`) [9](#0-8) 

`WalletConnectProvider` always calls the latest `process` via `processRef.current`: [10](#0-9) 

React re-renders are asynchronous. There is a non-zero window between when the Redux store is updated (wallet switch) and when the component re-renders and produces a new closure with the updated `currentFingerprint`. Any WalletConnect session request that arrives and is processed in that window uses the stale value.

### Impact Explanation

During the staleness window, a dapp paired with wallet A (fingerprint X) sends a request for a command such as `chia_takeOffer` or `chia_signMessageByAddress`. The stale check `currentFingerprint (X) === pair.fingerprint (X)` passes. Because `requiresSync` is false, no live re-fetch occurs. `dispatchAsPair` then executes the command in the main process against the currently active wallet B (fingerprint Y) — a wallet the dapp was never authorized for.

- **`chia_takeOffer`**: Unauthorized offer acceptance spending wallet B's XCH/CAT/NFT funds — Critical.
- **`chia_signMessageByAddress` / `chia_signMessageById`**: Valid signatures produced under wallet B's keys for a dapp authorized only for wallet A — Critical signing-context confusion.
- **`chia_transferDID`**: Wallet B's DID transferred to an attacker-controlled address — Critical.
- **`chia_pushTransactions` / `chia_pushTx`**: Arbitrary pre-built spend bundles pushed against wallet B — Critical.

### Likelihood Explanation

The race window exists whenever the user switches wallets while a WalletConnect session is active. A malicious dapp can deliberately time its requests: it can observe that the user is interacting with the wallet (e.g., via repeated polling of `chia_getWallets` or `chia_getOffersCount`, which are always allowed and have no sync requirement) and send a high-impact request immediately after detecting a wallet change. The confirmation dialog that appears does not prominently display which wallet key will be used, so a user who just switched wallets may confirm the dialog believing it applies to their new wallet.

### Recommendation

Apply the same live re-fetch guard that `requiresSync` commands already use to **all** commands before the fingerprint authorization check, not only those marked `requiresSync`. Concretely, move the `forceRefetch: true` fingerprint fetch and re-verification block (lines 58–81) to execute unconditionally before line 38, or at minimum add `requiresSync: true` to every dapp command that can mutate wallet state (`chia_takeOffer`, `chia_signMessageByAddress`, `chia_signMessageById`, `chia_transferDID`, `chia_mintNFT`, `chia_mintBulk`, `chia_pushTransactions`, `chia_pushTx`, `chia_updateDIDMetadata`, `chia_setNFTDID`, `chia_createNewDIDWallet`).

### Proof of Concept

1. User logs into wallet A (fingerprint X). A malicious dapp pairs with wallet A and is granted `chia_takeOffer` and `chia_getWallets`.
2. The dapp begins polling `chia_getWallets` every second to monitor the active wallet.
3. User switches to wallet B (fingerprint Y). The Redux store updates, but the React component has not yet re-rendered — `currentFingerprint` in the closure is still X.
4. The dapp detects the wallet change (next `chia_getWallets` returns wallet B's wallets) and immediately sends a `chia_takeOffer` request for a crafted offer that transfers wallet B's XCH to the attacker.
5. `handleProcess` runs: `pair.fingerprint = X`, `currentFingerprint (stale) = X` → check passes. `requiresSync` is false → no re-fetch. `dispatchAsPair` executes `take_offer` against the currently active wallet B.
6. The confirmation dialog appears. The user, confused by the unexpected dialog, may dismiss or confirm it. If confirmed, wallet B's funds are spent without the dapp ever having been authorized for wallet B.

### Citations

**File:** packages/gui/src/hooks/useWalletConnectCommand.tsx (L11-12)
```typescript
export default function useWalletConnectCommand() {
  const { data: currentFingerprint, isLoading } = useGetLoggedInFingerprintQuery();
```

**File:** packages/gui/src/hooks/useWalletConnectCommand.tsx (L37-46)
```typescript
    // verify if pair allows the requested fingerprint
    const requestedFingerprint = fingerprint ?? currentFingerprint;
    if (
      typeof requestedFingerprint !== 'number' ||
      !requestedFingerprint ||
      requestedFingerprint !== pair.fingerprint ||
      currentFingerprint !== pair.fingerprint
    ) {
      throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
    }
```

**File:** packages/gui/src/hooks/useWalletConnectCommand.tsx (L54-82)
```typescript
    if (commandMetadata.requiresSync) {
      log('Waiting for sync');
      await waitForWalletSync();

      const fingerprintRequest = store.dispatch(
        api.endpoints.getLoggedInFingerprint.initiate(undefined, { forceRefetch: true }),
      );

      try {
        const fingerprintAfterSync = await fingerprintRequest.unwrap();

        // verify if current fingerprint after sync is still correct
        const requestedFingerprintAfterSync = fingerprint ?? fingerprintAfterSync;
        if (
          typeof requestedFingerprintAfterSync !== 'number' ||
          !requestedFingerprintAfterSync ||
          requestedFingerprintAfterSync !== pair.fingerprint ||
          fingerprintAfterSync !== pair.fingerprint
        ) {
          throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
        }

        if (fingerprint && fingerprint !== fingerprintAfterSync) {
          throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.INTERNAL_ERROR);
        }
      } finally {
        fingerprintRequest.unsubscribe();
      }
    }
```

**File:** packages/gui/src/electron/commands/getDappCommandMetadata.ts (L7-13)
```typescript
export function getDappCommandMetadata(dappCommand: string): DappCommandMetadata {
  const dappCommandSchema = getDappCommandSchema(dappCommand);

  return {
    requiresSync: dappCommandSchema.requiresSync === true,
  };
}
```

**File:** packages/gui/src/electron/commands/Commands.ts (L364-369)
```typescript
    dapp: [
      {
        command: 'chia_takeOffer',
        title: () => i18n._(/* i18n */ { id: 'Take Offer' }),
      },
    ],
```

**File:** packages/gui/src/electron/commands/Commands.ts (L392-420)
```typescript
    dapp: [
      {
        command: 'chia_signMessageByAddress',
        title: () => i18n._(/* i18n */ { id: 'Sign Message by Address' }),
      },
    ],
  },

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

**File:** packages/gui/src/electron/commands/Commands.ts (L685-706)
```typescript
    dapp: [
      {
        command: 'chia_pushTransactions',
        title: () => i18n._(/* i18n */ { id: 'Push Transactions' }),
        message: () => i18n._(/* i18n */ { id: 'Push a list of transactions to the blockchain via the wallet' }),
      },
    ],
  },

  'chia_full_node.push_tx': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Push Transaction' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm pushing this transaction.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Push' }),
    params: [{ name: 'spend_bundle', label: () => i18n._(/* i18n */ { id: 'Spend Bundle' }), type: 'json' }],
    dapp: [
      {
        command: 'chia_pushTx',
        title: () => i18n._(/* i18n */ { id: 'Push Transaction' }),
        message: () => i18n._(/* i18n */ { id: 'Push a spend bundle (transaction) to the blockchain' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/Commands.ts (L778-783)
```typescript
    dapp: [
      {
        command: 'chia_mintNFT',
        title: () => i18n._(/* i18n */ { id: 'Mint NFT' }),
      },
    ],
```

**File:** packages/gui/src/electron/commands/Commands.ts (L987-993)
```typescript
    dapp: [
      {
        command: 'chia_transferDID',
        title: () => i18n._(/* i18n */ { id: 'Transfer DID' }),
      },
    ],
  },
```

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L260-261)
```typescript
  const processRef = useRef(process);
  processRef.current = process;
```
