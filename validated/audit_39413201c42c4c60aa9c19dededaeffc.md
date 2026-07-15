### Title
WalletConnect `chia_sendTransaction` Accepts Arbitrary `wallet_id` Hidden from Confirmation Dialog, Enabling Cross-Asset Spend Confusion — (`packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

A WalletConnect dApp granted `chia_sendTransaction` permission can substitute any `wallet_id` (e.g., a CAT wallet) in place of the default XCH wallet (id=1). Because `wallet_id` is declared `hide: true` in the confirmation schema and the amount is always humanized as `mojo-to-xch`, the user's approval dialog shows an XCH send while the actual RPC call targets a different wallet type. This is a direct analog to H-09: just as a Spartan pool accepted an arbitrary synth address without checking it belonged to that pool's token, `chia_sendTransaction` accepts an arbitrary wallet context without validating it is the standard XCH wallet.

---

### Finding Description

The `chia_wallet.send_transaction` command definition in `Commands.ts` declares `wallet_id` with `hide: true` and sets a default of `wallet_id: 1` (XCH), but the dApp is permitted to override this with any numeric wallet ID: [1](#0-0) 

The `wallet_id` field is explicitly hidden from the confirmation dialog (`hide: true`), and the `amount` field is always humanized as `mojo-to-xch` regardless of the actual wallet type being targeted: [2](#0-1) 

`parseDappParams` confirms that a dApp can supply `walletId: 2` (or any other value) and it will override the default, passing through to the daemon: [3](#0-2) 

Neither `parseDappParams` nor `dispatchPairRequest` validate that `wallet_id` must equal `1` for `chia_sendTransaction`. The only guards in `dispatchPairRequest` are fingerprint, network, and command-allowlist checks — none of which constrain the wallet_id value: [4](#0-3) 

The `humanizeParamValue.ts` file further confirms that the CAT name lookup for `wallet_id` is explicitly left as a TODO and never executed: [5](#0-4) 

---

### Impact Explanation

A dApp with `chia_sendTransaction` permission calls it with `wallet_id: <CAT_wallet_id>`. The user's confirmation dialog displays:

- **Title**: "Send Transaction"
- **Amount**: e.g., `100 XCH` (mojo-to-xch humanization applied unconditionally)
- **Address**: attacker-controlled address
- **wallet_id**: **not shown** (hidden)

The user approves believing they are sending XCH. The actual RPC dispatched to the Chia daemon is `send_transaction` with the CAT wallet's ID, spending CAT tokens instead. This causes the user to sign and broadcast a spend of the wrong asset to the wrong destination without informed consent.

This matches the allowed impact: **"WalletConnect state that causes a user to approve the wrong asset, amount, or destination."**

---

### Likelihood Explanation

- The attacker only needs a WalletConnect pairing with `chia_sendTransaction` in the granted command list — a standard "spending" permission that users routinely grant to DeFi dApps.
- No key compromise, phishing, or cryptographic break is required.
- The bypass path (`pair.bypass.includes(command)`) makes this silently executable without any confirmation at all if the user previously granted bypass for `chia_sendTransaction`. [6](#0-5) 

---

### Recommendation

1. **Enforce `wallet_id = 1` for `chia_sendTransaction`**: Add a validation step in `parseDappParams` or the command handler that rejects any `wallet_id` other than `1` for `chia_sendTransaction`, since this command is semantically scoped to the standard XCH wallet.

2. **Remove `hide: true` from `wallet_id`**: Display the wallet ID (and ideally the resolved wallet name/type) in the confirmation dialog so users can see which wallet is being spent.

3. **Resolve wallet name in confirmation display**: The TODO in `humanizeParamValue.ts` (`// TODO add lookupCat`) should be implemented so that `chia_spendCAT` confirmations show the actual CAT name, not just a numeric wallet ID.

---

### Proof of Concept

A malicious dApp with `chia_sendTransaction` permission executes:

```javascript
// dApp has been granted chia_sendTransaction at pairing time
// wallet_id 6 is the user's USDC CAT wallet

await client.request({
  topic: session.topic,
  chainId: 'chia:mainnet',
  request: {
    method: 'chia_sendTransaction',
    params: {
      amount: '1000000',   // displayed as 0.000001 XCH to user
      fee: '0',
      address: 'xch1attacker...',
      walletId: 6,         // CAT wallet — hidden from dialog
    },
  },
});
```

The user sees the confirmation dialog titled **"Send Transaction"** showing `0.000001 XCH` to the attacker address. `wallet_id: 6` is hidden. Upon approval, the daemon receives `send_transaction` with `wallet_id=6`, spending from the CAT wallet instead of the XCH wallet. [7](#0-6) [8](#0-7)

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L131-177)
```typescript
  'chia_wallet.send_transaction': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Send Transaction' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm this blockchain transaction.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Send' }),
    params: [
      {
        name: 'amount',
        label: () => i18n._(/* i18n */ { id: 'Amount' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
      },
      {
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
      },
      { name: 'address', label: () => i18n._(/* i18n */ { id: 'Address' }), type: 'string' },
      {
        name: 'wallet_id',
        label: () => i18n._(/* i18n */ { id: 'Wallet Id' }),
        type: 'number',
        hide: true,
      },
      {
        name: 'memos',
        label: () => i18n._(/* i18n */ { id: 'Memos' }),
        type: 'json',
        isOptional: true,
        hide: true,
      },
      {
        name: 'puzzle_decorator',
        label: () => i18n._(/* i18n */ { id: 'Puzzle Decorator' }),
        type: 'json',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_sendTransaction',
        title: () => i18n._(/* i18n */ { id: 'Send Transaction' }),
        requiresSync: true,
        defaults: { wallet_id: 1 },
      },
    ],
  },
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

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L28-54)
```typescript
  // verify if the command is allowed for this pair
  if (!pair.commands.includes(command)) {
    throw new WcError(`Command not allowed for this pair.`, WcErrorCode.UNAUTHORIZED_METHOD);
  }

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

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L56-59)
```typescript
  // if command is bypassed return true
  if (pair.bypass.includes(command)) {
    return process(context);
  }
```

**File:** packages/gui/src/electron/commands/humanizeParamValue.ts (L16-31)
```typescript
async function formatMojoCat(amount: unknown, data: Record<string, unknown>): Promise<string> {
  const mojo = parseMojos(amount);

  const formatted = mojoToCatLocaleString(mojo);
  const walletIdRaw = data.wallet_id;

  if (walletIdRaw === undefined || walletIdRaw === null) {
    return formatted;
  }

  return formatted;

  // TODO add lookupCat
  // const cat = await lookupCat(walletIdRaw as number | string);
  // return cat?.displayName ? `${formatted} ${cat.displayName}` : formatted;
}
```
