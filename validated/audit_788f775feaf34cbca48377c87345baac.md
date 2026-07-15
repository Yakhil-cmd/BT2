### Title
WalletConnect Multi-NFT Royalty Confirmation Displays Systematically Understated "Total Amount with Royalties" Due to Shared `splitAmount` Accounting Error - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` divides the fungible spend amount by the number of NFTs before applying each NFT's royalty percentage. This causes the "Total Amount with Royalties" shown in the WalletConnect confirmation dialog to be exactly `1/n` of the correct value (where `n` is the number of NFTs), systematically misleading the user into approving a `chia_wallet.take_offer` transaction that costs significantly more than displayed.

### Finding Description

`formatAmountWithRoyalties` computes the displayed royalty total as:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← shared divisor
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [1](#0-0) 

This computes: `royaltyDisplayed = (amount / n) × Σrᵢ / 10000`

The correct calculation — applying each NFT's royalty to the **full** fungible amount — is: `royaltyCorrect = amount × Σrᵢ / 10000`

The ratio is `royaltyDisplayed / royaltyCorrect = 1/n`. With 2 NFTs the display is 50% of the real cost; with 10 NFTs it is 10%.

The own test suite encodes this bug as the expected value:

```
// Two NFTs: royalty_percentage 500 (5%) and 10 (0.1%), spend 100,000,000 mojos
// Displayed: 0.00010255 XCH  ← splitAmount = 50,000,000 applied to each
// Correct:   0.0001051  XCH  ← full 100,000,000 applied to each
``` [2](#0-1) 

The incorrect `amountWithRoyalties` value is then placed into `DisplayWalletDeltaItem` and rendered verbatim in the WalletConnect confirmation dialog under the label **"Total Amount with Royalties"**: [3](#0-2) 

The same label appears for `kind: 'cat'` and `kind: 'wallet'` spending lines as well: [4](#0-3) 

### Impact Explanation

When a WalletConnect-connected dapp sends `chia_wallet.take_offer` containing an offer for multiple NFTs with royalties, the user's confirmation dialog shows a "Total Amount with Royalties" that is `1/n` of the actual cost. The user reads this as the total they will spend, approves, and the daemon executes the offer at the correct (higher) royalty cost. This is a direct, concrete balance loss: the user is deceived into signing a spend of more XCH (or CAT) than the approval screen states.

This fits the allowed High impact: *"WalletConnect state that causes a user to approve … the wrong … amount."*

### Likelihood Explanation

Any WalletConnect-paired dapp can submit a `chia_wallet.take_offer` request. The offer string itself is cryptographically valid (signed by the NFT seller); the dapp only needs to relay it. NFTs with non-zero `royalty_percentage` are common on mainnet. The discrepancy grows linearly with the number of NFTs in the offer, making it trivially amplifiable by bundling more NFTs.

### Recommendation

Replace the `splitAmount` division with per-NFT application of the full amount:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Remove the `splitAmount` variable entirely.

### Proof of Concept

1. Attacker (malicious dapp) relays a valid `take_offer` offer string containing 10 NFTs each with `royalty_percentage = 1000` (10%) and a fungible XCH request of 1 XCH (1,000,000,000,000 mojos).
2. GUI calls `parseCommandDisplay('chia_wallet.take_offer', { offer: '...' })`.
3. `formatAmountWithRoyalties` computes:
   - `splitAmount = 1,000,000,000,000 / 10 = 100,000,000,000`
   - `royaltyAmount = 10 × (100,000,000,000 × 1000) / 10000 = 100,000,000,000`
   - `totalAmount = 1,100,000,000,000 mojos` → displayed as **1.1 XCH**
4. Correct value: `royaltyAmount = 10 × (1,000,000,000,000 × 1000) / 10000 = 1,000,000,000,000` → **2.0 XCH**
5. User sees "Total Amount with Royalties: 1.1 XCH", approves, and the daemon settles the offer at **2.0 XCH**. [5](#0-4) [6](#0-5)

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L130-135)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}
            {line.symbol && <span className="ml-1">{line.symbol}</span>}
          </div>
        )}
```
