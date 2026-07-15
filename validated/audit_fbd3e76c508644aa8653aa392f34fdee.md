### Title
WalletConnect `chia_sendTransaction` Always Displays Amount as XCH Regardless of Wallet Type, Causing Approval Confusion for CAT Transfers - (File: packages/gui/src/electron/commands/Commands.ts)

### Summary

The `chia_wallet.send_transaction` WalletConnect command hardcodes `humanize: 'mojo-to-xch'` for the `amount` parameter display, while simultaneously hiding the `wallet_id` field from the user. A malicious dapp can call `chia_sendTransaction` with a CAT wallet ID, causing the confirmation dialog to display the amount using XCH decimal scaling (÷10¹²) instead of CAT decimal scaling (÷10³) — a factor of 10⁹ difference — while the user has no visibility into which wallet is actually being spent.

### Finding Description

The `chia_wallet.send_transaction` command definition statically assigns `humanize: 'mojo-to-xch'` to the `amount` parameter and marks `wallet_id` as `hide: true`: [1](#0-0) 

The `humanize: 'mojo-to-xch'` path in `humanizeParamValue.ts` unconditionally calls `mojoToChiaLocaleString`, which divides by 10¹²: [2](#0-1) 

By contrast, the dedicated `chia_wallet.cat_spend` command correctly uses `humanize: 'mojo-to-cat'` (÷10³): [3](#0-2) 

The `chia_sendTransaction` dapp command accepts an arbitrary `wallet_id` (defaulting to `1`, but overridable by the dapp): [4](#0-3) 

Because `wallet_id` is hidden from the confirmation dialog, the user cannot see that a CAT wallet is being targeted. The Chia wallet RPC `send_transaction` is a generic method that accepts any `wallet_id`, including CAT wallets.

### Impact Explanation

A malicious dapp connected via WalletConnect calls `chia_sendTransaction` with:
- `wallet_id: <CAT wallet id>` (e.g., wallet 2)
- `amount: 1_000_000_000` (1,000,000 CAT = 1,000,000,000 mojos)

The confirmation dialog displays:
- **Shown to user:** `0.000000001 XCH` (1,000,000,000 ÷ 10¹²)
- **Actual transaction:** `1,000,000 CAT` (1,000,000,000 ÷ 10³)

The user approves what appears to be a negligible XCH dust amount, but the wallet executes a transfer of 1,000,000 CAT tokens. The `wallet_id` being hidden removes the only other signal that could alert the user to the mismatch.

This matches **High impact**: WalletConnect state causes a user to approve the wrong asset and wrong amount.

### Likelihood Explanation

Any dapp that has an active WalletConnect session with `chia_sendTransaction` permission can trigger this. The permission is granted at the session level, not per-call. The dapp only needs to deviate from the default `wallet_id: 1` to target a CAT wallet the user holds.

### Recommendation

The `chia_wallet.send_transaction` command must resolve the actual wallet type from `wallet_id` at display time and apply the correct humanization (`mojo-to-xch` for standard wallet, `mojo-to-cat` for CAT/CRCAT wallets). Additionally, `wallet_id` should not be hidden — it should be displayed (ideally resolved to a human-readable wallet name) so the user can verify which wallet is being spent. The `humanizeParamValue` function already has a `data` parameter containing all sibling params (including `wallet_id`) that can be used for this lookup, mirroring the existing (but stubbed-out) `lookupCat` TODO in `formatMojoCat`. [5](#0-4) 

### Proof of Concept

1. Establish a WalletConnect session with a Chia GUI wallet that holds both XCH (wallet 1) and a CAT (wallet 2, e.g., 500,000 CAT = 500,000,000 mojos).
2. From the dapp, send a `chia_sendTransaction` session request with params:
   ```json
   { "wallet_id": 2, "amount": 500000000, "fee": 0, "address": "<attacker_address>" }
   ```
3. Observe the confirmation dialog: it displays `0.0000005 XCH` (500,000,000 ÷ 10¹²) with no wallet type or wallet ID visible.
4. User clicks **Send** believing they are sending negligible XCH dust.
5. The wallet executes `send_transaction` against wallet 2, transferring 500,000 CAT to the attacker's address. [6](#0-5)

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

**File:** packages/gui/src/electron/commands/Commands.ts (L179-212)
```typescript
  'chia_wallet.cat_spend': {
    title: () => i18n._(/* i18n */ { id: 'Confirm CAT Spend' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm this CAT spend.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Send' }),
    params: [
      { name: 'wallet_id', label: () => i18n._(/* i18n */ { id: 'Wallet Id' }), type: 'number' },
      { name: 'address', label: () => i18n._(/* i18n */ { id: 'Address' }), type: 'string' },
      {
        name: 'amount',
        label: () => i18n._(/* i18n */ { id: 'Amount' }),
        type: 'bigint',
        humanize: 'mojo-to-cat',
      },
      {
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
      },
      {
        name: 'memos',
        label: () => i18n._(/* i18n */ { id: 'Memos' }),
        type: 'json',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_spendCAT',
        title: () => i18n._(/* i18n */ { id: 'Spend CAT' }),
        requiresSync: true,
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/humanizeParamValue.ts (L11-14)
```typescript
function formatMojoXch(amount: unknown, networkPrefix?: string): string {
  const formatted = mojoToChiaLocaleString(amount as string | number);
  return networkPrefix ? `${formatted} ${networkPrefix.toUpperCase()}` : formatted;
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
