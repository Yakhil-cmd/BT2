### Title
Royalty Amount Understatement in Multi-NFT WalletConnect Offer Approval Display - (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the payment amount by the number of NFTs before computing each NFT's royalty. When a WalletConnect `take_offer` or `create_offer_for_ids` command involves multiple NFTs with royalties, the displayed "total amount with royalties" shown in the approval dialog is materially understated. A user approves believing they are spending less than they actually will.

### Finding Description

In `formatAmountWithRoyalties`, the royalty for each NFT is computed on `splitAmount = amount / N` (integer division, truncating) rather than on the full `amount`:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts (lines 363-367)
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [1](#0-0) 

Each NFT's royalty is an independent percentage of the **full** payment amount. Dividing `amount` by the NFT count before multiplying by each royalty percentage produces a result that is `1/N` of the correct royalty per NFT, so the total royalty displayed is `1/N` of what it should be (where N = number of NFTs).

The correct formula is:
```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

The `amountWithRoyalties` field produced by this function is surfaced in the WalletConnect confirmation dialog (`DisplayWalletDelta`) shown to the user before they approve a spend. [2](#0-1) 

The function is invoked through `withRoyaltyTotals` → `walletDeltaToDisplay` → `parseCommandDisplay`, which drives the approval UI for `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids` WalletConnect commands. [3](#0-2) 

### Impact Explanation

**High — WalletConnect state spoofing causing a user to approve the wrong spend amount.**

Concrete example with 2 NFTs:
- User pays **1 XCH** (1,000,000,000,000 mojos) to receive NFT-A (500 bps royalty) and NFT-B (100 bps royalty).
- **Displayed** (buggy): `splitAmount = 500,000,000,000`; royalty = `25,000,000,000 + 5,000,000,000 = 30,000,000,000`; total shown = **1.03 XCH**.
- **Actual** (correct): royalty = `50,000,000,000 + 10,000,000,000 = 60,000,000,000`; total deducted = **1.06 XCH**.
- The user approves a transaction they believe costs 1.03 XCH but is actually charged 1.06 XCH — a 0.03 XCH discrepancy that scales with royalty rates and number of NFTs.

The existing test suite encodes the wrong expected value (`0.00010255` XCH) and passes, masking the bug. [4](#0-3) 

### Likelihood Explanation

Any unprivileged dApp connected via WalletConnect can trigger this path by constructing an offer that involves two or more NFTs with royalties. No leaked keys, host compromise, or social engineering beyond the normal WalletConnect connection flow is required. Multi-NFT offers are a standard use case in the Chia NFT ecosystem.

### Recommendation

Remove the erroneous division by `royaltyPercentages.length`. Each royalty percentage applies independently to the full `amount`:

```diff
- const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
-   (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
+   (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
```

Update the corresponding test expectations in `parseCommandDisplay.test.ts` to reflect the corrected values.

### Proof of Concept

Using the existing test scaffold in `parseCommandDisplay.test.ts`, with two NFTs having royalty percentages of 500 bps and 10 bps and a payment of 100,000,000 mojos:

- **Current (buggy) output**: `amountWithRoyalties = '0.00010255'` (102,550,000 mojos)
- **Correct output**: royalty = `(100,000,000 × 500)/10,000 + (100,000,000 × 10)/10,000 = 5,000,000 + 100,000 = 5,100,000`; total = **105,100,000 mojos = `0.0001051` XCH**

The gap (2,550,000 mojos ≈ 2.5%) grows proportionally with royalty rates and number of NFTs. A dApp offering 5 NFTs each with a 10% royalty would display a total 80% lower than the actual deduction. [2](#0-1)

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
