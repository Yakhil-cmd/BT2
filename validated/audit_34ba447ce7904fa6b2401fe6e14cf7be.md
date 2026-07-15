### Title
Incorrect Royalty Amount Displayed in WalletConnect Offer Confirmation Due to `splitAmount` Division Bug - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in the WalletConnect offer confirmation pipeline incorrectly divides the fungible asset amount by the number of NFTs before applying each royalty percentage. This causes the displayed `amountWithRoyalties` in the WalletConnect approval dialog to be significantly understated when an offer contains multiple NFTs with royalties, leading users to approve transactions that cost materially more than shown.

### Finding Description

In `packages/gui/src/electron/commands/parseCommandDisplay.ts`, the function `formatAmountWithRoyalties` computes the total cost including royalties as follows:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The `splitAmount = amount / numNFTs` step is wrong. Each NFT's royalty should be applied to the **full** fungible amount, not to a fraction of it. The correct formula is:

```
totalRoyalties = Σ (amount × royaltyPercentage_i / 10_000)
totalAmount    = amount + totalRoyalties
```

The code instead computes:

```
totalRoyalties = Σ ((amount / numNFTs) × royaltyPercentage_i / 10_000)
```

This underestimates royalties by a factor of `numNFTs`. For example, with 2 NFTs (5% and 0.1% royalty) and 0.0001 XCH:

| Approach | Royalties | Total shown |
|---|---|---|
| Code (`splitAmount`) | 2,550,000 mojos | **0.00010255 XCH** |
| Correct (full amount) | 5,100,000 mojos | **0.0001051 XCH** |

The test suite encodes the wrong expected value, confirming the bug is baked in: [2](#0-1) 

This is an analog to the `applyInterest` inconsistency: the same royalty concept is computed three different ways across the codebase:

1. **`formatAmountWithRoyalties`** (WalletConnect dialog): `splitAmount` per NFT — **wrong**
2. **`offerBuilderDataToOffer.ts`**: compounding multiplier applied to the running total per NFT
3. **`OfferBuilderXCHSection.tsx`**: additive — each royalty payment added to the full base amount [3](#0-2) [4](#0-3) 

### Impact Explanation

`formatAmountWithRoyalties` feeds the `amountWithRoyalties` field displayed in the WalletConnect confirmation dialog for both `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`. [5](#0-4) 

A user approving a WalletConnect `take_offer` request sees a total cost that is understated by a factor proportional to the number of NFTs. With 10 NFTs each carrying a 10% royalty, the dialog would show 1.1 XCH total while the actual on-chain cost is 2 XCH. The user approves based on the wrong figure and loses the difference.

### Likelihood Explanation

Any WalletConnect-connected dApp can craft a `take_offer` payload containing multiple NFTs with royalties. No special privileges, leaked keys, or host compromise are required. The user's only defense is the confirmation dialog, which displays the incorrect amount.

### Recommendation

Replace the `splitAmount` division with the correct per-NFT full-amount calculation:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

Update the corresponding test expectations in `parseCommandDisplay.test.ts` to reflect the corrected values.

### Proof of Concept

1. A malicious dApp connects via WalletConnect.
2. It sends `chia_wallet.take_offer` with an offer containing 10 NFTs, each with a 10% royalty, requesting 1 XCH total.
3. `formatAmountWithRoyalties` computes `splitAmount = 1 XCH / 10 = 0.1 XCH`, then `royaltyAmount = 10 × (0.1 × 10%) = 0.1 XCH`, displaying **1.1 XCH** total.
4. The correct total is `1 + 10 × (1 × 10%) = 2 XCH`.
5. The user approves, believing the cost is 1.1 XCH; the blockchain deducts 2 XCH. [6](#0-5) [7](#0-6)

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L431-435)
```typescript
  return {
    spending: withRoyaltyTotals(spendingItems, spending, receivingLines),
    receiving: withRoyaltyTotals(receivingItems, receiving, spendingLines),
    fee: fee !== undefined ? mojoToChiaLocaleString(fee) : undefined,
  };
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L438-460)
```typescript
export async function parseCommandDisplay(command: string, params: Record<string, unknown>) {
  if (command === 'chia_wallet.take_offer') {
    if (!params.offer || typeof params.offer !== 'string') {
      throw new Error('Offer is not valid');
    }

    const offerSummary = await getOfferSummary(params.offer);
    if (!offerSummary || !offerSummary.summary || !offerSummary.success) {
      throw new Error('Offer is not valid');
    }

    const { summary } = offerSummary;

    const walletDelta = offerSummaryToWalletDelta(summary);
    const walletInfos = await getWalletInfos();
    const assetKinds = offerSummaryAssetKinds(summary);
    const royaltyPercentages = offerSummaryRoyaltyPercentages(summary);
    const fees = parseMojos(summary.fees);

    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, fees),
    };
  }
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L314-334)
```typescript
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

**File:** packages/gui/src/util/offerBuilderDataToOffer.ts (L349-352)
```typescript
          const royaltyMultiplier = 1 + +royaltyPercentageStr / 10_000;
          const spendingXch = pendingXchOffer.spendingAmount.minus(feeInMojos);
          const newSpendingXch = spendingXch.multipliedBy(royaltyMultiplier).plus(feeInMojos);
          pendingXchOffer.spendingAmount = newSpendingXch;
```

**File:** packages/gui/src/components/offers2/OfferBuilderXCHSection.tsx (L42-58)
```typescript
    let amountWithRoyaltiesLocal = chiaToMojo(amount);
    const rows: Record<string, any>[] = [];
    Object.entries(allRoyalties).forEach(([nftId, royaltyPaymentsLocal]) => {
      const matchingPayment = royaltyPaymentsLocal?.find((payment) => payment.asset === 'xch');
      if (matchingPayment) {
        amountWithRoyaltiesLocal = amountWithRoyaltiesLocal.plus(matchingPayment.amount);
        rows.push({
          nftId,
          payment: {
            ...matchingPayment,
            displayAmount: mojoToChiaLocaleString(matchingPayment.amount),
          },
        });
      }
    });

    return [mojoToChiaLocaleString(amountWithRoyaltiesLocal), rows];
```
