### Title
WalletConnect `chia_sendTransaction` Hides Source `wallet_id` from User Confirmation, Enabling Spend from Wrong Wallet - (File: `packages/gui/src/electron/commands/Commands.ts`)

### Summary
The `chia_sendTransaction` WalletConnect dapp command marks `wallet_id` as hidden (`hide: true`) in the user-facing confirmation dialog and defaults it to `1` (the standard XCH wallet). A connected dapp can supply any `wallet_id` under the current fingerprint, causing funds to be spent from a different wallet (e.g., a CAT or CR-CAT wallet) without the user being able to see or verify the source wallet at approval time.

### Finding Description
In `Commands.ts`, the `chia_wallet.send_transaction` command definition marks `wallet_id` with `hide: true`: [1](#0-0) 

The dapp alias `chia_sendTransaction` inherits these params and sets `defaults: { wallet_id: 1 }`: [2](#0-1) 

`parseDappParams` applies the default only when the dapp omits the field, and explicitly allows the dapp to override it with any wallet ID: [3](#0-2) 

This is confirmed by the test suite, which shows a dapp can pass `walletId: 2` and it will be used instead of the default: [4](#0-3) 

The fingerprint guard in `dispatchPairRequest` only verifies that the logged-in key matches the pair's fingerprint — it does not validate which `wallet_id` (sub-wallet) the dapp is targeting: [5](#0-4) 

Because `wallet_id` is hidden from the confirmation dialog, the user sees the amount and destination address but has no way to know which wallet (XCH, CAT, CR-CAT, etc.) is the source of the spend.

### Impact Explanation
A dapp granted `chia_sendTransaction` permission can specify `wallet_id: N` where N is any sub-wallet under the current fingerprint (e.g., a CAT wallet, CR-CAT wallet, or a second XCH wallet). The user approves the transaction believing funds come from their default XCH wallet (wallet ID 1), but the spend is actually executed from wallet N. This constitutes an unauthorized transfer of the wrong asset — XCH, CAT, or CR-CAT — without the user's informed consent, matching the Critical/High impact class of "causes a user to approve the wrong asset, identity, amount, or status."

### Likelihood Explanation
Any dapp that has been granted `chia_sendTransaction` via WalletConnect can exploit this. The user must have connected the dapp and approved the command, but the dapp is an unprivileged external actor that controls the `wallet_id` parameter. No additional privileges, key leakage, or host compromise is required.

### Recommendation
Remove `hide: true` from the `wallet_id` parameter in the `chia_wallet.send_transaction` command definition so the source wallet name and ID are displayed in the confirmation dialog. Additionally, consider restricting the dapp-supplied `wallet_id` to only the standard XCH wallet (ID 1) for `chia_sendTransaction`, or require explicit per-wallet-type permissions.

### Proof of Concept
1. User connects a dapp via WalletConnect and grants `chia_sendTransaction` permission.
2. The dapp calls `chia_sendTransaction` with `{ amount: "1000", fee: "0", address: "xch1...", walletId: 5 }` where wallet 5 is a CAT wallet.
3. `parseDappParams` normalizes `walletId` → `wallet_id: 5` and passes it through.
4. The confirmation dialog shows amount and destination address but **not** the source wallet (hidden by `hide: true`).
5. The user approves, believing they are sending XCH from their standard wallet.
6. The backend executes `send_transaction` with `wallet_id: 5`, spending CAT tokens from the user's CAT wallet instead of XCH from wallet 1.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L149-154)
```typescript
      {
        name: 'wallet_id',
        label: () => i18n._(/* i18n */ { id: 'Wallet Id' }),
        type: 'number',
        hide: true,
      },
```

**File:** packages/gui/src/electron/commands/Commands.ts (L169-176)
```typescript
    dapp: [
      {
        command: 'chia_sendTransaction',
        title: () => i18n._(/* i18n */ { id: 'Send Transaction' }),
        requiresSync: true,
        defaults: { wallet_id: 1 },
      },
    ],
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L40-48)
```typescript
  // apply all default values if they are not provided (aliases can use them)
  // devs can apply default values that are not in params list
  if (dappCommandSchema.defaults) {
    for (const [key, value] of Object.entries(dappCommandSchema.defaults)) {
      if (nextParams[key] === undefined) {
        nextParams[key] = value;
      }
    }
  }
```

**File:** packages/gui/src/electron/commands/parseDappParams.test.ts (L63-76)
```typescript
      expect(
        parseDappParams(
          'chia_sendTransaction',
          serialize({
            amount: '1',
            fee: '0',
            address: 'txch1address',
            walletId: 2,
          }),
        ),
      ).toMatchObject({
        wallet_id: 2,
      });
    });
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L40-54)
```typescript
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
