### Title
Multi-NFT Royalty Amount Understated in WalletConnect Offer Confirmation Dialog - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the payment amount by the number of NFTs before computing each royalty, producing a systematically understated "You Spend" total in the WalletConnect confirmation dialog for `chia_takeOffer` and `chia_createOfferForIds`. A user approves based on a lower displayed cost than they will actually pay on-chain.

### Finding Description
When a WalletConnect dApp triggers `chia_takeOffer` or `chia_createOfferForIds` involving multiple NFTs that each carry royalties, `parseCommandDisplay` calls `formatAmountWithRoyalties` to compute the `amountWithRoyalties` field shown in the "You Spend" section of the confirmation dialog.

The function contains an accounting error:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← wrong
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

`splitAmount` divides the full payment by the number of NFTs before multiplying by each royalty percentage. Each NFT's royalty should instead be computed on the **full** payment amount. The correct formula is:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

The existing test suite at `parseCommandDisplay.test.ts` lines 251–335 encodes and asserts the **buggy** output as the expected value, confirming the defect is present and undetected:

- Payment: 100,000,000 mojos (0.0001 XCH)
- NFT1 royalty: 500 (5%), NFT2 royalty: 10 (0.1%)
- **Displayed** (buggy): 0.00010255 XCH (102,550,000 mojos)
- **Correct**: 0.0001051 XCH (105,100,000 mojos)
- **Understatement**: 2,550,000 mojos (~50% of actual royalties hidden)

The error grows with the number of NFTs: with N NFTs, each royalty is computed on `amount/N` instead of `amount`, so the displayed total approaches `amount` as N increases, hiding all royalties.

### Impact Explanation
The `amountWithRoyalties` field is rendered directly in the WalletConnect confirmation dialog's "You Spend" section (`Confirm.tsx` `WalletDeltaSection`). A user sees a lower total cost than they will actually pay. They may approve a transaction they would reject if shown the true cost, or they may lack sufficient balance for the actual on-chain royalty payments. This constitutes WalletConnect state causing a user to approve the wrong amount — **High** impact under the allowed scope.

### Likelihood Explanation
Any WalletConnect-connected dApp can present a `chia_takeOffer` or `chia_createOfferForIds` request containing two or more NFTs with royalties. No special privileges are required. Multi-NFT offers are a normal use case in Chia NFT marketplaces. The bug is triggered deterministically whenever `royaltyPercentages.length > 1`.

### Recommendation
Remove the division by `royaltyPercentages.length` in `formatAmountWithRoyalties`. Compute each royalty on the full `amount`:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test assertions in `parseCommandDisplay.test.ts` to reflect the corrected values.

### Proof of Concept

**Scenario**: WalletConnect dApp calls `chia_takeOffer` with an offer where the user pays 100,000,000 mojos for two NFTs — NFT1 with 5% royalty (500 basis points) and NFT2 with 0.1% royalty (10 basis points).

**Buggy path** in `formatAmountWithRoyalties`: [1](#0-0) 

1. `splitAmount = 100_000_000n / 2n = 50_000_000n`
2. `royaltyAmount = (50_000_000 × 500)/10_000 + (50_000_000 × 10)/10_000 = 2_500_000 + 50_000 = 2_550_000`
3. `totalAmount = 102_550_000` → displayed as **0.00010255 XCH**

**Correct calculation**:
1. `royaltyAmount = (100_000_000 × 500)/10_000 + (100_000_000 × 10)/10_000 = 5_000_000 + 100_000 = 5_100_000`
2. `totalAmount = 105_100_000` → should display **0.0001051 XCH**

The `amountWithRoyalties` string is placed into the `DisplayWalletDeltaItem` returned by `walletDeltaToDisplay`: [2](#0-1) 

This is then rendered in the WalletConnect confirmation dialog's "You Spend" section: [3](#0-2) 

The test at lines 310–335 asserts the buggy value `0.00010255` as expected, confirming the defect is baked in: [4](#0-3)

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L431-435)
```typescript
  return {
    spending: withRoyaltyTotals(spendingItems, spending, receivingLines),
    receiving: withRoyaltyTotals(receivingItems, receiving, spendingLines),
    fee: fee !== undefined ? mojoToChiaLocaleString(fee) : undefined,
  };
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L195-205)
```typescript
          {i18n._(/* i18n */ { id: 'You Spend' })}
        </div>
        <div className="mt-1.5 flex flex-col gap-1.5">
          {walletDelta.spending.length === 0 ? (
            <span className="text-sm text-chia-text-secondary">{i18n._(/* i18n */ { id: 'Nothing' })}</span>
          ) : (
            walletDelta.spending.map((line, i) => (
              <OfferLineRow key={offerLineKey(line, i)} line={line} networkPrefix={networkPrefix} />
            ))
          )}
        </div>
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L310-335)
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
  });
```
