### Title
WalletConnect `create_offer_for_ids` Confirmation Dialog Omits Fee — User Approves Hidden XCH Deduction - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The WalletConnect confirmation dialog for `chia_wallet.create_offer_for_ids` never displays the `fee` parameter to the user. A malicious dApp can pass an arbitrarily large fee, and the user will approve the offer creation seeing only the offered/requested assets — not the XCH fee being deducted from their balance.

### Finding Description
`parseCommandDisplay` handles two WalletConnect commands. For `take_offer`, it correctly extracts and forwards the fee from the offer summary:

```ts
// parseCommandDisplay.ts line 455-458
const fees = parseMojos(summary.fees);
return {
  walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, fees),
};
```

For `create_offer_for_ids`, the `fee` parameter present in `params` is silently dropped — `undefined` is hardcoded as the fee argument:

```ts
// parseCommandDisplay.ts line 477-479
return {
  walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, undefined),
};
```

`walletDeltaToDisplay` only emits a fee field when the argument is not `undefined`:

```ts
// parseCommandDisplay.ts line 434
fee: fee !== undefined ? mojoToChiaLocaleString(fee) : undefined,
```

And `Confirm.tsx` only renders the "Offer Fees" row when `walletDelta.fee !== undefined`:

```ts
// Confirm.tsx line 221-229
{walletDelta.fee !== undefined && (
  <div className="px-5 py-2.5">
    ...{walletDelta.fee} {feeUnit}
  </div>
)}
```

Meanwhile, `Commands.ts` explicitly declares `fee` as a valid (optional) parameter for `create_offer_for_ids` that is forwarded to the node RPC and deducted from the user's XCH balance:

```ts
// Commands.ts line 307-312
{
  name: 'fee',
  label: () => i18n._(/* i18n */ { id: 'Fee' }),
  type: 'bigint',
  humanize: 'mojo-to-xch',
  isOptional: true,
},
```

### Impact Explanation
A malicious dApp connected via WalletConnect calls `chia_wallet.create_offer_for_ids` with a large `fee` value (e.g., 10 XCH). The confirmation dialog shows the user only the assets being offered and requested — the fee row is entirely absent. The user approves, and the node deducts the full fee from their XCH spendable balance. This is a direct, unprivileged XCH balance loss caused by WalletConnect state that causes the user to approve the wrong amount.

**Allowed impact match:** "High: Corruption, spoofing, or unsafe trust of … WalletConnect state that causes a user to approve … the wrong asset, identity, amount, destination, or status."

### Likelihood Explanation
Any dApp that has been granted WalletConnect permission for `chia_createOfferForIds` can trigger this. No additional privileges, leaked keys, or social engineering beyond the initial (legitimate) WalletConnect pairing are required. The user has no way to detect the hidden fee from the confirmation UI.

### Recommendation
In the `create_offer_for_ids` branch of `parseCommandDisplay`, extract and forward `params.fee` to `walletDeltaToDisplay` the same way `take_offer` forwards `summary.fees`:

```ts
// parseCommandDisplay.ts — create_offer_for_ids branch
const fee = params.fee !== undefined ? parseMojos(params.fee) : undefined;
return {
  walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, fee),
};
```

### Proof of Concept
1. Pair a dApp with the Chia GUI via WalletConnect and obtain `chia_createOfferForIds` permission.
2. Call `chia_wallet.create_offer_for_ids` with a normal offer payload and `fee: 10000000000000` (10 XCH).
3. Observe the confirmation dialog: it shows "You Spend / You Receive" asset rows but no "Offer Fees" row.
4. User clicks Confirm.
5. The node creates the offer and deducts 10 XCH as the network fee — the user's balance drops by 10 XCH beyond what the dialog indicated.

**Root cause lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L434-434)
```typescript
    fee: fee !== undefined ? mojoToChiaLocaleString(fee) : undefined,
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L477-479)
```typescript
    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, undefined),
    };
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L221-229)
```typescript
      {walletDelta.fee !== undefined && (
        <div className="px-5 py-2.5">
          <div className="text-xs font-semibold uppercase tracking-wider text-chia-text-muted">
            {i18n._(/* i18n */ { id: 'Offer Fees' })}
          </div>
          <div className="mt-0.5 text-sm font-medium text-chia-text">
            {walletDelta.fee} {feeUnit}
          </div>
        </div>
```

**File:** packages/gui/src/electron/commands/Commands.ts (L307-312)
```typescript
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
        isOptional: true,
      },
```
