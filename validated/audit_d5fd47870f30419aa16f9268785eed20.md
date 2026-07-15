### Title
Incorrect Royalty Amount Displayed in WalletConnect Offer Confirmation When Multiple NFTs Are Involved - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the fungible amount by the number of NFTs before computing each NFT's royalty. This causes the "Total Amount with Royalties" shown in the WalletConnect signing confirmation dialog to be understated by a factor proportional to the number of NFTs in the offer. A user approves a `take_offer` or `create_offer_for_ids` WalletConnect request believing they will spend less than they actually will.

### Finding Description

In `formatAmountWithRoyalties`:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);  // ← incorrect divisor
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The function first splits the full amount by the number of NFTs, then applies each NFT's royalty percentage to that reduced `splitAmount`. In the Chia protocol, each NFT's royalty is calculated on the **full** fungible amount, not a fraction of it. The correct formula is:

```
totalRoyalty = Σ (amount × royaltyPercentage_i / 10_000)
```

**Concrete example** (from the existing test at line 251):
- Amount: `100_000_000` mojos (0.0001 XCH)
- NFT1 royalty: 500 (5%), NFT2 royalty: 10 (0.1%)

| | Displayed (buggy) | Correct |
|---|---|---|
| NFT1 royalty | `50_000_000 × 500 / 10_000 = 2_500_000` | `100_000_000 × 500 / 10_000 = 5_000_000` |
| NFT2 royalty | `50_000_000 × 10 / 10_000 = 50_000` | `100_000_000 × 10 / 10_000 = 100_000` |
| Total shown | `0.00010255 XCH` | `0.0001051 XCH` |

The test itself is written to match the buggy output: [2](#0-1) 

The `display` object produced by `parseCommandDisplay` is passed directly into the WalletConnect confirmation dialog: [3](#0-2) 

The dialog renders `amountWithRoyalties` as "Total Amount with Royalties" — the primary figure a user relies on before clicking Confirm. [4](#0-3) 

### Impact Explanation

A user accepting a multi-NFT offer via WalletConnect sees an understated total spend in the confirmation dialog. With N NFTs, the displayed royalty total is understated by a factor of N. The user approves the offer believing they will spend less XCH/CAT than the transaction actually deducts. This constitutes **corruption of WalletConnect state that causes a user to approve the wrong amount**, matching the High-severity criterion: *"Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status."*

### Likelihood Explanation

Any dApp connected via WalletConnect can send a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request containing an offer with two or more NFTs that each carry royalties. No special privileges are required — the dApp only needs an established WalletConnect session, which is the normal operating mode. The bug is triggered automatically whenever `royaltyPercentages.length > 1`.

### Recommendation

Remove the `splitAmount` division. Each NFT's royalty must be computed on the full `amount`:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [5](#0-4) 

The test at line 251–335 must also be updated to reflect the correct expected value (`0.0001051` instead of `0.00010255`).

### Proof of Concept

1. Establish a WalletConnect session with the Chia GUI.
2. From the dApp, call `chia_wallet.take_offer` with an offer blob that encodes:
   - Offered: two NFTs, NFT-A (royalty 500 = 5%) and NFT-B (royalty 10 = 0.1%)
   - Requested: 0.0001 XCH
3. The GUI confirmation dialog shows **"Total Amount with Royalties: 0.00010255 XCH"**.
4. The user clicks Confirm.
5. The Chia daemon executes the offer and deducts the correct royalties: **0.0001051 XCH** — approximately 2.4% more than the user was shown.

The understatement scales linearly with the number of NFTs: with 3 NFTs the displayed royalty is 1/3 of the true value, with 4 NFTs it is 1/4, and so on.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L363-368)
```typescript
  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L319-321)
```typescript
            amount: '0.0001',
            amountWithRoyalties: '0.00010255',
          },
```

**File:** packages/gui/src/electron/main.tsx (L329-344)
```typescript
          const display = await parseCommandDisplay(commandId, parsedParams);

          const confirmResult = await openReactDialog<ConfirmDialogResult, ConfirmProps>(
            mainWindow,
            Confirm,
            {
              networkPrefix,
              command: commandId,
              data: parsedParams,
              title,
              message,
              confirmLabel,
              destructive,
              rows,
              pair,
              display,
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L19-23)
```typescript
export type DisplayWalletDeltaItem =
  | { kind: 'xch'; amount: string; amountWithRoyalties?: string }
  | { kind: 'wallet'; walletId: string; amount: string; walletName?: string; amountWithRoyalties?: string }
  | { kind: 'cat'; amount: string; assetId: string; symbol?: string; amountWithRoyalties?: string }
  | { kind: 'nft'; nftId: string; name?: string; previewUrl?: string; royaltyPercentage?: number };
```
