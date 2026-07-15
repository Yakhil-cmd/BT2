### Title
Multi-NFT Offer Royalty Amount Understated in WalletConnect Confirmation Dialog - (`File: packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the fungible payment amount by the number of NFTs before computing each NFT's royalty contribution. When a WalletConnect `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request involves multiple NFTs with royalties, the "Total Amount with Royalties" shown in the confirmation dialog is understated by a factor proportional to the number of NFTs. The user approves the offer believing they will spend less than the blockchain will actually charge.

### Finding Description

In `formatAmountWithRoyalties`:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

The function first divides `amount` by the count of NFTs (`royaltyPercentages.length`) to produce `splitAmount`, then applies each NFT's royalty percentage to that reduced base. This is mathematically wrong. Each NFT's royalty is independently owed on the **full** fungible amount, not on `amount / N`.

**Correct formula:**
```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

**Actual formula used:**
```
splitAmount   = amount / N
royaltyAmount = Σ ((amount / N) × royaltyPercentage_i / 10_000)
              = Σ (amount × royaltyPercentage_i / 10_000) / N   ← understated by N
```

The result is that the displayed `amountWithRoyalties` is understated by a factor of N (the number of NFTs in the offer). The test suite in `parseCommandDisplay.test.ts` encodes and asserts this wrong value (`'0.00010255'` instead of the correct `'0.0001051'`), confirming the bug is present and untested-against. [1](#0-0) 

The `withRoyaltyTotals` function calls `formatAmountWithRoyalties` for every fungible spending line and attaches the result as `amountWithRoyalties`, which is then rendered in the WalletConnect confirmation dialog (`Confirm.tsx`) as "Total Amount with Royalties." [2](#0-1) 

The confirmation dialog renders this field directly to the user before they click "Send": [3](#0-2) 

### Impact Explanation

A user presented with a multi-NFT offer via WalletConnect sees a "Total Amount with Royalties" that is lower than what the blockchain will actually deduct. They approve the transaction based on the understated figure. The actual on-chain spend is higher — the correct royalty is enforced by the blockchain puzzle, not the GUI. The user loses more XCH or CAT than the confirmation dialog indicated, with no further warning or recourse.

This matches the High impact category: **"Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status."**

### Likelihood Explanation

Any unprivileged actor can craft a valid multi-NFT offer (two or more NFTs each with a non-zero `royalty_percentage`) and deliver it to a victim via WalletConnect using the `chia_wallet.take_offer` command. No special access, leaked keys, or social engineering beyond the normal WalletConnect pairing flow is required. The bug is triggered automatically by the GUI's own parsing logic whenever `royaltyPercentages.length > 1`.

### Recommendation

Remove the erroneous division by `royaltyPercentages.length`. Each NFT's royalty must be computed against the full `amount`:

```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  // Each NFT's royalty is owed on the full amount, not on amount/N
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
  ...
}
```

Update the corresponding test assertion in `parseCommandDisplay.test.ts` from `'0.00010255'` to `'0.0001051'`. [4](#0-3) 

### Proof of Concept

**Scenario:** A WalletConnect dapp sends `chia_wallet.take_offer` for an offer where the user spends 100,000,000 mojos (0.0001 XCH) to receive two NFTs — NFT-A with 5% royalty (500 basis points) and NFT-B with 0.1% royalty (10 basis points).

**Correct total the user will actually pay on-chain:**
- Royalty for NFT-A: 100,000,000 × 500 / 10,000 = 5,000,000 mojos
- Royalty for NFT-B: 100,000,000 × 10 / 10,000 = 100,000 mojos
- Total: 105,100,000 mojos = **0.0001051 XCH**

**What the GUI displays (buggy):**
- splitAmount = 100,000,000 / 2 = 50,000,000
- Royalty for NFT-A: 50,000,000 × 500 / 10,000 = 2,500,000 mojos
- Royalty for NFT-B: 50,000,000 × 10 / 10,000 = 50,000 mojos
- Total displayed: 102,550,000 mojos = **0.00010255 XCH**

The user approves seeing 0.00010255 XCH but the blockchain deducts 0.0001051 XCH — a silent overpayment of 2,550,000 mojos per such offer. The discrepancy grows with the number of NFTs and the magnitude of royalty percentages. [5](#0-4)

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
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
