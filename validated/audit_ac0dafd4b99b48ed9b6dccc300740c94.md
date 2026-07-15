### Title
WalletConnect Offer Approval Displays Underestimated Royalty Total When Multiple NFTs Are Present - (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
`formatAmountWithRoyalties` in `parseCommandDisplay.ts` incorrectly divides the fungible amount by the number of NFTs before computing each NFT's royalty, causing the `amountWithRoyalties` shown in the WalletConnect confirmation dialog to be a factor of N lower than the actual on-chain deduction when N > 1 NFTs are in the offer.

### Finding Description
In `formatAmountWithRoyalties` (lines 354–375), when a user is about to accept a `chia_wallet.take_offer` or approve a `chia_wallet.create_offer_for_ids` command via WalletConnect, the GUI computes the displayed total-with-royalties as:

```ts
const splitAmount = amount / BigInt(royaltyPercentages.length);   // integer-divides by N
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [1](#0-0) 

This yields:

```
displayed_royalty = (amount / N) × Σ(royaltyPct_i) / 10000
```

But the Chia protocol charges each NFT's royalty against the **full** fungible amount, so the correct formula is:

```
actual_royalty = amount × Σ(royaltyPct_i) / 10000
```

The displayed royalty is therefore `1/N` of the actual royalty. Additionally, the BigInt integer division `amount / BigInt(N)` truncates, compounding the error.

The `amountWithRoyalties` field produced here is surfaced directly in the WalletConnect approval dialog via `walletDeltaToDisplay` → `withRoyaltyTotals`. [2](#0-1) 

### Impact Explanation
A user accepting a multi-NFT offer via WalletConnect sees a total XCH (or CAT) cost that is significantly lower than what the blockchain will actually deduct. For example, buying 2 NFTs each with a 5% royalty for 1 XCH:

- **Displayed**: 1 + (0.5 × 5% + 0.5 × 5%) = **1.05 XCH**
- **Actual on-chain**: 1 + (1 × 5% + 1 × 5%) = **1.10 XCH**

The user approves the transaction believing they are spending 1.05 XCH but 1.10 XCH is deducted. With high royalty percentages (up to the protocol maximum) and many NFTs, the gap grows proportionally. This is a direct, concrete asset loss caused by a corrupted amount displayed in the WalletConnect signing approval flow.

### Likelihood Explanation
Any unprivileged actor can create an offer containing multiple NFTs with non-zero royalty percentages and share it via WalletConnect. No leaked keys, host compromise, or social engineering beyond presenting a legitimate-looking offer is required. The victim only needs to accept the offer through the WalletConnect approval dialog.

### Recommendation
Remove the `splitAmount` division. Each NFT's royalty must be calculated against the full `amount`:

```ts
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [3](#0-2) 

### Proof of Concept
The existing test at line 251–335 of `parseCommandDisplay.test.ts` already encodes the wrong expected value and confirms the bug:

- Offer: 0.0001 XCH for 2 NFTs (royalties 500 = 5%, 10 = 0.1%)
- Test asserts `amountWithRoyalties: '0.00010255'`
  - Computed as: `(100000000 / 2) × (500 + 10) / 10000 = 2550000` mojos added → **0.00010255 XCH**
- Correct value: `100000000 × (500 + 10) / 10000 = 5100000` mojos added → **0.0001051 XCH** [4](#0-3) 

The test was written to match the buggy implementation. With high-royalty NFTs (e.g., 50% each) and 3 NFTs, the displayed amount would be 3× lower than the actual deduction, causing material, measurable asset loss upon WalletConnect approval.

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L377-394)
```typescript
function withRoyaltyTotals(
  items: DisplayWalletDeltaItemWithKey[],
  amounts: Record<string, bigint>,
  oppositeSideLines: DisplayWalletDeltaItem[],
): DisplayWalletDeltaItem[] {
  const royaltyPercentages = royaltyPercentagesForSide(oppositeSideLines);

  return items.map(({ key, line }) => {
    if (line.kind === 'nft') {
      return line;
    }

    const amount = amounts[key];
    const amountWithRoyalties = amount ? formatAmountWithRoyalties(line, amount, royaltyPercentages) : undefined;

    return amountWithRoyalties ? { ...line, amountWithRoyalties } : line;
  });
}
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
