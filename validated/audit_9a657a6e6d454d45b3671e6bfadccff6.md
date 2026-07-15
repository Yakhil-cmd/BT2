Based on my investigation of the actual production code, here is my assessment:

### Title
Hidden `wallet_id` Override via camelCase Normalization Allows dApp to Send From Arbitrary Wallet Without User Awareness — (`packages/gui/src/electron/commands/parseDappParams.ts`, `Commands.ts`)

### Summary

A WalletConnect dApp can pass `walletId: N` (camelCase) in a `chia_sendTransaction` request. `parseDappParams` normalizes it to `wallet_id: N` via `toSnakeCase` before the allowlist check, which passes because `wallet_id` is a declared schema param. The default `wallet_id: 1` is then skipped. The confirmation dialog hides `wallet_id` entirely (`hide: true`), so the user approves a transaction without knowing which wallet it originates from.

### Finding Description

**Step 1 — camelCase normalization:** [1](#0-0) 

`toSnakeCase` converts `walletId` → `wallet_id` before any field validation.

**Step 2 — `wallet_id` is in the allowlist for `chia_sendTransaction`:** [2](#0-1) 

The param is declared with `hide: true`, so it passes the allowlist check at line 34–38 of `parseDappParams.ts`.

**Step 3 — Default is skipped when dApp supplies the value:** [3](#0-2) 

`wallet_id: 1` default is only applied when `nextParams[key] === undefined`. The dApp-supplied value prevents this.

**Step 4 — Confirmed by the test suite itself:** [4](#0-3) 

The test explicitly asserts that `walletId: 2` in dApp params produces `wallet_id: 2` in the output — this is the exact attack path.

**Step 5 — `wallet_id` is hidden from the confirmation dialog:** [5](#0-4) 

`humanizeDappCommand` calls `humanizeParams(dappCommandSchema.params, data)`. Params with `hide: true` are excluded from the `rows` shown to the user. The user sees `amount` (humanized as XCH via `mojo-to-xch`), `fee`, and `address` — but **not** which wallet the funds come from.

**Step 6 — The misleading display:** The `amount` field carries `humanize: 'mojo-to-xch'` regardless of the actual wallet type. If the dApp targets a CAT wallet (e.g., `wallet_id: 2`), the dialog still labels the amount as XCH, while the daemon sends CAT tokens. [6](#0-5) 

### Impact Explanation

A user with multiple wallets (XCH wallet ID 1, CAT wallet ID 2) pairs with a dApp. The dApp calls `chia_sendTransaction` with `walletId: 2`, `amount: 1000000`, `address: attacker_address`. The confirmation dialog shows "Send 0.000001 XCH to attacker_address." The user approves. The daemon sends 1,000,000 mojos of CAT tokens from wallet 2 to the attacker. The user has approved the wrong asset from the wrong wallet with no indication of either.

This satisfies: *"causes a user to approve … the wrong asset, identity, amount, destination, or status."*

### Likelihood Explanation

- Requires an active WalletConnect pair (user must have connected the dApp)
- The dApp can enumerate wallet IDs via `chia_getWallets` (a bypassable read command)
- No additional privileges needed beyond the pair
- The behavior is mechanically confirmed by the existing test suite

### Recommendation

1. Remove `wallet_id` from the dApp-controllable params list for `chia_sendTransaction`, or
2. Remove `hide: true` from `wallet_id` so the wallet name/ID is always shown in the confirmation dialog, and
3. Ensure the humanization label reflects the actual asset type of the target wallet, not a hardcoded "mojo-to-xch" label.

### Proof of Concept

```json
// WalletConnect session_request payload
{
  "method": "chia_sendTransaction",
  "params": {
    "amount": "1000000",
    "fee": "0",
    "address": "xch1attacker...",
    "walletId": 2
  }
}
```

`parseDappParams('chia_sendTransaction', params)` returns `{ amount: 1000000n, fee: 0n, address: 'xch1attacker...', wallet_id: 2 }`. The confirmation dialog shows amount/fee/address only. User approves. CAT tokens are sent from wallet 2.

### Citations

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L12-14)
```typescript
  const parsedParams = toSnakeCase(JSONbig({ useNativeBigInt: true }).parse(params), {
    deep: !dappCommandSchema.preserveNestedDataKeys,
  });
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L42-48)
```typescript
  if (dappCommandSchema.defaults) {
    for (const [key, value] of Object.entries(dappCommandSchema.defaults)) {
      if (nextParams[key] === undefined) {
        nextParams[key] = value;
      }
    }
  }
```

**File:** packages/gui/src/electron/commands/Commands.ts (L136-154)
```typescript
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
```

**File:** packages/gui/src/electron/commands/parseDappParams.test.ts (L63-75)
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
```

**File:** packages/gui/src/electron/commands/humanizeDappCommand.ts (L4-15)
```typescript
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
```
