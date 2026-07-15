### Title
WalletConnect `chia_getWalletAddresses` Leaks Addresses for Unauthorized Wallet Keys via Unvalidated `fingerprints` Array Parameter - (File: `packages/gui/src/electron/utils/dispatchPairRequest.ts`, `packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

A WalletConnect dapp authorized for a single wallet fingerprint can silently retrieve wallet addresses for **any other fingerprint** stored in the user's keychain by supplying an arbitrary `fingerprints` array to `chia_getWalletAddresses`. The pair-level fingerprint guard in `dispatchPairRequest` only inspects the scalar `params.fingerprint` field; the plural `params.fingerprints` array that `daemon.get_wallet_addresses` forwards to the daemon is never validated against the pair's authorized fingerprint. Because the command carries `allowConfirmationBypass: true`, a dapp that has been granted bypass permission executes this cross-wallet enumeration with zero user interaction.

---

### Finding Description

The `dispatchPairRequest` function is the sole authorization gate for all WalletConnect commands. Its fingerprint check reads the scalar key `fingerprint` from the parsed params:

```
const { fingerprint } = params;
const requestedFingerprint = fingerprint ?? loggedInFingerprint;
if (... requestedFingerprint !== pair.fingerprint) { throw ... }
``` [1](#0-0) 

For `chia_getWalletAddresses` the dapp-facing schema declares a `fingerprints` (plural, type `json`) parameter — not `fingerprint` (singular). `parseDappParams` only strips a field literally named `fingerprint` when it is absent from the schema; it leaves `fingerprints` untouched. [2](#0-1) 

Because `params.fingerprint` is `undefined` for this command, `requestedFingerprint` falls back to `loggedInFingerprint`, which equals `pair.fingerprint` — the check passes. The `fingerprints` array is then forwarded verbatim to the daemon via `sendCommand`: [3](#0-2) 

The daemon's `get_wallet_addresses` RPC derives addresses from the keychain for every fingerprint listed in the array, regardless of which wallet is currently logged in. No code anywhere in the GUI validates that the entries in `fingerprints` match the pair's authorized fingerprint.

The command is also marked `allowConfirmationBypass: true`: [4](#0-3) 

A dapp that has been granted bypass permission (via `chia_requestPermissions`) can therefore call `chia_getWalletAddresses` with an arbitrary `fingerprints` array silently, with no confirmation dialog shown to the user.

---

### Impact Explanation

A dapp authorized for wallet key A can enumerate the receive addresses of wallet keys B, C, … N stored in the user's keychain without any additional user approval. This constitutes a **bypass of WalletConnect approval scope**: the user consented to share data for one key; the dapp obtains data for all keys. Concretely:

- All XCH/CAT/NFT receive addresses for every other wallet key on the device are disclosed to the dapp.
- With bypass permission the disclosure is silent and repeatable.
- The attacker can correlate on-chain activity across all of the user's wallet keys, breaking the privacy isolation that separate keys are intended to provide, and can use the harvested addresses for targeted phishing or to link pseudonymous identities.

This matches the **High** impact category: *Bypass of WalletConnect approval … with direct security impact*.

---

### Likelihood Explanation

- Any dapp that has been granted `chia_getWalletAddresses` (a read-only, bypass-eligible command that users are likely to approve without scrutiny) can exploit this immediately.
- No special privileges, leaked keys, or host compromise are required — only a valid WalletConnect pairing for any one fingerprint.
- The bypass path means exploitation requires zero runtime interaction from the user after initial pairing.

---

### Recommendation

Inside `dispatchPairRequest` (or in a dedicated validator called before `sendCommand`), when the parsed params contain a `fingerprints` array, assert that every element equals `pair.fingerprint`. For example:

```typescript
if (Array.isArray(params.fingerprints)) {
  const invalid = (params.fingerprints as unknown[]).some(
    (f) => f !== pair.fingerprint,
  );
  if (invalid) {
    throw new WcError(
      'Fingerprints not allowed for this pair',
      WcErrorCode.UNAUTHORIZED_METHOD,
    );
  }
}
```

Alternatively, strip the `fingerprints` param entirely in the dapp schema and have the handler inject `[pair.fingerprint]` automatically, so the dapp cannot influence which keys are queried. [5](#0-4) 

---

### Proof of Concept

1. Attacker operates a malicious dapp and establishes a WalletConnect pairing with the victim's Chia GUI for fingerprint `111111`.
2. During pairing, the dapp requests `chia_getWalletAddresses` and `chia_requestPermissions`; the user approves both (they appear innocuous).
3. The dapp calls `chia_requestPermissions` with `commands: ["chia_getWalletAddresses"]` to obtain bypass permission, eliminating future confirmation dialogs.
4. The dapp sends a WalletConnect `session_request`:
   ```json
   {
     "method": "chia_getWalletAddresses",
     "params": {
       "fingerprints": [222222, 333333, 444444],
       "count": 10
     }
   }
   ```
5. `WalletConnectProvider` parses the request; `fingerprint` (singular) is absent so `parsedFingerprint` is `undefined`; `commandParams` contains `{ fingerprints: [222222,333333,444444], count: 10 }`. [6](#0-5) 
6. `dispatchPairRequest` extracts `params.fingerprint` → `undefined`; falls back to `loggedInFingerprint` = `111111` = `pair.fingerprint` → **check passes**. [7](#0-6) 
7. Because `chia_getWalletAddresses` is in the pair's bypass list, `process(context)` is called immediately with no dialog. [8](#0-7) 
8. `sendCommand('get_wallet_addresses', 'daemon', { fingerprints: [222222,333333,444444], count: 10 })` is issued; the daemon returns receive addresses for all three foreign wallet keys. [9](#0-8) 
9. The dapp receives the full address list for wallets it was never authorized for, with no user notification.

### Citations

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L33-54)
```typescript
  const { fingerprint } = params;

  // verify if the network is the same as the pair's network
  if (isMainnetValue !== pair.mainnet) {
    throw new WcError(`Network mismatch`, WcErrorCode.UNSUPPORTED_CHAINS);
  }

  // verify if the requested fingerprint is allowed for this pair
  const requestedFingerprint = fingerprint ?? loggedInFingerprint;
  if (typeof requestedFingerprint !== 'number' || !requestedFingerprint || requestedFingerprint !== pair.fingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }

  const context = {
    pair,
    fingerprint: requestedFingerprint,
  };

  // Dapps may not switch the active key for an existing pair.
  if (fingerprint !== undefined && fingerprint !== loggedInFingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L57-58)
```typescript
  if (pair.bypass.includes(command)) {
    return process(context);
```

**File:** packages/gui/src/electron/commands/Commands.ts (L2565-2603)
```typescript
  'daemon.get_wallet_addresses': {
    title: () => i18n._(/* i18n */ { id: 'Get wallet addresses for one or more wallet keys' }),
    message: () => i18n._(/* i18n */ { id: 'Requests the addresses for a specific wallet keys' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Proceed' }),
    params: [
      {
        name: 'fingerprints',
        label: () => i18n._(/* i18n */ { id: 'Fingerprints' }),
        type: 'json',
        isOptional: true,
      },
      {
        name: 'index',
        label: () => i18n._(/* i18n */ { id: 'Index' }),
        type: 'number',
        isOptional: true,
      },
      {
        name: 'count',
        label: () => i18n._(/* i18n */ { id: 'Count' }),
        type: 'number',
        isOptional: true,
      },
      {
        name: 'non_observer_derivation',
        label: () => i18n._(/* i18n */ { id: 'Non Observer Derivation' }),
        type: 'bool',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_getWalletAddresses',
        title: () => i18n._(/* i18n */ { id: 'Get wallet addresses for one or more wallet keys' }),
        transform: (data) => data.wallet_addresses,
        allowConfirmationBypass: true,
      },
    ],
  },
```

**File:** packages/gui/src/electron/main.tsx (L293-300)
```typescript
          const response = dappCommandSchema.handler
            ? await dappCommandSchema.handler(parsedParams, {
                ...context,
                sendNotification: sendRendererNotification,
                canBypassCommand: (requestedCommand) =>
                  DappCommands.get(requestedCommand)?.allowConfirmationBypass === true,
              })
            : await sendCommand(chiaCommand, destination, parsedParams);
```

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L353-366)
```typescript
      // parse fingerprint
      const { fingerprint, ...rest } = params;
      const commandParams = {
        ...rest,
      };

      const parsedFingerprint = parseFingerprint(fingerprint);
      if (parsedFingerprint !== undefined) {
        commandParams.fingerprint = parsedFingerprint;
      }

      log('method', method, commandParams);

      const result = await currentProcess(pairTopic, method, commandParams, { mainnet: isMainnet });
```
