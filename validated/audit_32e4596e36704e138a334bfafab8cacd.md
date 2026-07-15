### Title
Missing `humanize` Conversion on `amount` and `fee` in `chia_data_layer.add_mirror` WalletConnect Command Causes Raw Mojo Values Displayed in Confirmation Dialog - (File: `packages/gui/src/electron/commands/Commands.ts`)

### Summary
The `chia_data_layer.add_mirror` WalletConnect command definition omits the `humanize: 'mojo-to-xch'` field on both its `amount` and `fee` parameters. As a result, the WalletConnect confirmation dialog renders these values as raw bigint mojo strings (e.g., `"1000000000000000"`) with no unit label, instead of the human-readable XCH equivalent (e.g., `"1000 XCH"`). A malicious dApp can exploit this to cause a user to unknowingly approve a DataLayer mirror transaction that locks a far larger XCH amount than they intended.

### Finding Description
In `Commands.ts`, the `humanize` field on a `ParamSchema` controls whether a bigint mojo value is converted to a readable XCH or CAT string before being shown in the confirmation dialog. Every other command that presents a monetary `fee` or `amount` to the user correctly sets `humanize: 'mojo-to-xch'` (e.g., `chia_wallet.send_transaction`, `chia_data_layer.delete_mirror`, `chia_data_layer.make_offer`).

The `chia_data_layer.add_mirror` command is the exception:

```typescript
'chia_data_layer.add_mirror': {
  params: [
    { name: 'id',     ..., type: 'string' },
    { name: 'urls',   ..., type: 'json'   },
    { name: 'amount', ..., type: 'bigint' },   // ← no humanize
    { name: 'fee',    ..., type: 'bigint',     // ← no humanize
      isOptional: true },
  ],
``` [1](#0-0) 

When `humanize` is absent, `humanizeParamValue` falls through to the `'bigint'` branch and returns the raw integer string:

```typescript
case 'bigint':
  return BigInt(value as string | number | bigint).toString();
``` [2](#0-1) 

So a dApp that sends `amount: 1_000_000_000_000_000n` (= 1 000 XCH) causes the dialog to display `"Amount: 1000000000000000"` — an opaque number with no currency unit.

Compare with `chia_data_layer.delete_mirror`, which correctly applies `humanize: 'mojo-to-xch'` to its `fee`: [3](#0-2) 

And `chia_wallet.send_transaction`, which applies it to both `amount` and `fee`: [4](#0-3) 

The `humanizeDappCommand` pipeline that feeds the confirmation dialog relies entirely on the schema's `humanize` field; there is no fallback conversion for bigint monetary values: [5](#0-4) 

### Impact Explanation
`chia_addMirror` locks real XCH into a DataLayer mirror coin. A malicious dApp connected via WalletConnect can craft a request with an arbitrarily large `amount` in mojos. Because the confirmation dialog shows only the raw mojo integer with no unit, the user cannot distinguish `1000000000000` (1 XCH) from `1000000000000000` (1 000 XCH). Approving the dialog causes the full mojo amount to be locked on-chain. This constitutes a WalletConnect state spoofing issue that causes the user to display and approve the wrong amount, resulting in direct XCH loss.

### Likelihood Explanation
Any dApp that has been granted the `chia_addMirror` command permission can trigger this. WalletConnect permission grants are persistent, so a dApp that was legitimately granted the command can later send a malicious `amount`. The user has no way to detect the discrepancy from the confirmation dialog alone.

### Recommendation
Add `humanize: 'mojo-to-xch'` to both the `amount` and `fee` parameters of `chia_data_layer.add_mirror` in `Commands.ts`, consistent with every other command that presents monetary bigint values:

```typescript
{ name: 'amount', label: () => i18n._({ id: 'Amount' }), type: 'bigint', humanize: 'mojo-to-xch' },
{ name: 'fee',    label: () => i18n._({ id: 'Fee' }),    type: 'bigint', humanize: 'mojo-to-xch', isOptional: true },
```

Audit all other `type: 'bigint'` parameters across `Commands.ts` that represent XCH or CAT monetary values (e.g., `chia_wallet.nft_set_did_bulk` `fee`, `chia_wallet.set_auto_claim` `tx_fee`/`min_amount`) for the same omission.

### Proof of Concept
1. Connect a dApp to the Chia GUI via WalletConnect and obtain permission for `chia_addMirror`.
2. From the dApp, call `chia_addMirror` with `amount: 1000000000000000n` (1 000 XCH in mojos) and a valid store `id` and `urls`.
3. Observe the WalletConnect confirmation dialog: it shows `"Amount: 1000000000000000"` with no XCH label.
4. A user who clicks "Add" locks 1 000 XCH in the mirror coin, believing the number was a coin identifier or a small value.
5. For contrast, repeat with `chia_deleteMirror` (which has `humanize: 'mojo-to-xch'` on `fee`) and observe that the fee is correctly rendered as `"0.000005 XCH"`.

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

**File:** packages/gui/src/electron/commands/Commands.ts (L1197-1218)
```typescript
  'chia_data_layer.add_mirror': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Add Mirror' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm adding this mirror.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Add' }),
    params: [
      { name: 'id', label: () => i18n._(/* i18n */ { id: 'Store Id' }), type: 'string' },
      { name: 'urls', label: () => i18n._(/* i18n */ { id: 'URLs' }), type: 'json' },
      { name: 'amount', label: () => i18n._(/* i18n */ { id: 'Amount' }), type: 'bigint' },
      {
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_addMirror',
        title: () => i18n._(/* i18n */ { id: 'Add Mirror' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/Commands.ts (L1220-1241)
```typescript
  'chia_data_layer.delete_mirror': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Delete Mirror' }),
    message: () => i18n._(/* i18n */ { id: 'Are you sure you want to delete this mirror?' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Delete' }),
    destructive: true,
    params: [
      { name: 'coin_id', label: () => i18n._(/* i18n */ { id: 'Coin Id' }), type: 'string' },
      {
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_deleteMirror',
        title: () => i18n._(/* i18n */ { id: 'Delete Mirror' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/commands/humanizeParamValue.ts (L56-62)
```typescript
  switch (type) {
    case 'string':
    case 'number':
      return String(value);
    case 'bigint':
      return BigInt(value as string | number | bigint).toString();
    case 'bool':
```

**File:** packages/gui/src/electron/commands/humanizeDappCommand.ts (L1-16)
```typescript
import { getDappCommandSchema } from './getDappCommandSchema';
import { humanizeParams } from './humanizeParams';

export async function humanizeDappCommand(dappCommand: string, data: Record<string, unknown>, networkPrefix?: string) {
  const dappCommandSchema = getDappCommandSchema(dappCommand);

  const rows = await humanizeParams(dappCommandSchema.params, data, networkPrefix);

  return {
    destructive: dappCommandSchema.destructive === true,
    title: dappCommandSchema.title(),
    message: dappCommandSchema.message(),
    confirmLabel: dappCommandSchema.confirmLabel(),
    rows,
  };
}
```
