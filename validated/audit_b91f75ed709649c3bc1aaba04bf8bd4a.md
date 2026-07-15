### Title
WalletConnect Multi-NFT Offer Approval Dialog Displays Understated "Total Amount with Royalties" Due to Incorrect `splitAmount` Division - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` divides the total fungible amount by the number of NFTs before computing each NFT's royalty contribution. This causes the "Total Amount with Royalties" shown in the WalletConnect `Confirm` approval dialog to be systematically understated whenever a `take_offer` or `create_offer_for_ids` command involves more than one royalty-bearing NFT. A user who relies on this figure to decide whether to approve the command will approve a transaction that deducts more XCH/CAT from their wallet than the dialog indicated.

### Finding Description

`formatAmountWithRoyalties` is called from `withRoyaltyTotals`, which is called from `walletDeltaToDisplay`, which is called from `parseCommandDisplay`. `parseCommandDisplay` is invoked in `main.tsx` at two points — once for the direct-GUI confirmation flow (line 825) and once for the WalletConnect dApp pair flow (line 329) — and its result is passed as the `display.walletDelta` prop to the `Confirm` dialog. [1](#0-0) 

The flawed calculation:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by N
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

For N NFTs with royalty percentages R₁…Rₙ and total fungible amount A, this yields:

```
displayed royalty = (A / N) × (R₁ + R₂ + … + Rₙ) / 10 000
```

The correct formula (each NFT's royalty applies to the full trade amount) is:

```
correct royalty = A × (R₁ + R₂ + … + Rₙ) / 10 000
```

The displayed figure is exactly 1/N of the correct figure. The `Confirm` dialog renders this as "Total Amount with Royalties": [2](#0-1) 

The `parseCommandDisplay` call that feeds this dialog: [3](#0-2) [4](#0-3) 

By contrast, the regular offer builder uses the authoritative `nft_calculate_royalties` RPC, which receives the full fungible asset amounts and returns the correct per-NFT royalty: [5](#0-4) 

### Impact Explanation

**Concrete example — 3 NFTs each with 10 % royalty, 1 XCH trade:**

| | Displayed | Actual |
|---|---|---|
| Base amount | 1 XCH | 1 XCH |
| Royalties | 0.1 XCH (1/3 of correct) | 0.3 XCH |
| **Total** | **1.1 XCH** | **1.3 XCH** |

The user sees 1.1 XCH in the approval dialog and clicks "Confirm". The blockchain deducts 1.3 XCH. The 0.2 XCH difference is a direct, unrecoverable asset loss caused by approving the wrong amount.

This satisfies the **High** impact criterion: *"WalletConnect state that causes a user to approve … the wrong … amount."*

### Likelihood Explanation

Any WalletConnect-connected dApp can send a `take_offer` or `create_offer_for_ids` command containing multiple royalty-bearing NFTs. The dApp does not need elevated permissions beyond the standard `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` grant. The discrepancy scales linearly with the number of NFTs, so a dApp that bundles many NFTs into one offer maximises the gap between the displayed and actual cost. The user has no other figure in the dialog to cross-check against; the "Raw data" collapsible shows mojos, not a human-readable royalty total. [6](#0-5) 

### Recommendation

Remove the `/ BigInt(royaltyPercentages.length)` division. Each NFT's royalty should be calculated on the full `amount`:

```typescript
// Correct
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

This matches the semantics of the `nft_calculate_royalties` RPC used by the offer builder.

### Proof of Concept

The existing test in `parseCommandDisplay.test.ts` (lines 251–334) already demonstrates the bug: with 2 NFTs carrying royalties of 500 (5 %) and 10 (0.1 %) on 0.0001 XCH, the test asserts `amountWithRoyalties: '0.00010255'`. [7](#0-6) 

The correct value is:
- royalty₁ = 100 000 000 × 500 / 10 000 = 5 000 000 mojos
- royalty₂ = 100 000 000 × 10 / 10 000 = 100 000 mojos
- total = 105 100 000 mojos = **0.0001051 XCH**

The dialog shows **0.00010255 XCH** — understated by ~2.5 %. With N=3 NFTs of equal royalty the understatement reaches 66 %. A malicious dApp operator crafts an offer with many high-royalty NFTs, presents it via WalletConnect, and the victim approves based on the understated total.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L354-375)
```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;

  if (line.kind === 'xch') {
    return mojoToChiaLocaleString(totalAmount);
  }

  return mojoToCATLocaleString(totalAmount);
}
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```

**File:** packages/gui/src/electron/main.tsx (L329-329)
```typescript
          const display = await parseCommandDisplay(commandId, parsedParams);
```

**File:** packages/gui/src/electron/main.tsx (L825-825)
```typescript
        const display = await parseCommandDisplay(commandId, commandData);
```

**File:** packages/gui/src/components/offers2/OfferBuilderProvider.tsx (L110-118)
```typescript
  const requestedRoyaltiesRequest: CalculateRoyaltiesRequest = {
    royaltyAssets: requestedRoyaltyAssets,
    fungibleAssets: offeredFungibleAssets,
  };

  const offeredRoyaltiesRequest: CalculateRoyaltiesRequest = {
    royaltyAssets: offeredRoyaltyAssets,
    fungibleAssets: requestedFungibleAssets,
  };
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L310-334)
```typescript
    await expect(
      parseCommandDisplay('chia_wallet.take_offer', {
        offer: 'offer1...',
      }),
    ).resolves.toMatchObject({
      walletDelta: {
        spending: [
          {
            kind: 'xch',
            amount: '0.0001',
            amountWithRoyalties: '0.00010255',
          },
        ],
        receiving: [
          {
            kind: 'nft',
            royaltyPercentage: 500,
          },
          {
            kind: 'nft',
            royaltyPercentage: 10,
          },
        ],
      },
    });
```
