### Title
Understated "Total Amount with Royalties" in WalletConnect Take-Offer Confirmation Dialog When Multiple NFTs Are Involved - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary
In `formatAmountWithRoyalties` inside `parseCommandDisplay.ts`, the royalty amount shown to the user in the WalletConnect `take_offer` confirmation dialog is calculated by first dividing the fungible payment amount equally among all NFTs, then applying each NFT's royalty percentage to that split amount. This is the same class of accumulation/accounting bug as the external report: instead of summing `royaltyPercentage_i * fullAmount` for each NFT, the code sums `royaltyPercentage_i * (fullAmount / nftCount)`. The result is a systematically understated "Total Amount with Royalties" displayed to the user, who may approve a WalletConnect transaction believing they will spend less than the blockchain will actually deduct.

### Finding Description

`formatAmountWithRoyalties` in `parseCommandDisplay.ts` computes the displayed total as follows:

```ts
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by NFT count
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The correct calculation is to apply each NFT's royalty to the **full** payment amount, not to `amount / nftCount`. The correct formula is:

```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

With the current code, for N NFTs the displayed royalty is `1/N` of what it should be. For example, with two NFTs having royalties of 500 bp (5%) and 10 bp (0.1%) and a payment of 100,000,000 mojos (0.0001 XCH):

| | Displayed (buggy) | Correct |
|---|---|---|
| splitAmount | 50,000,000 | — |
| Royalty NFT1 (5%) | 2,500,000 | 5,000,000 |
| Royalty NFT2 (0.1%) | 50,000 | 100,000 |
| **Total shown** | **102,550,000** | **105,100,000** |

The test suite itself encodes this incorrect value as the expected output: [2](#0-1) 

The understated total is then rendered in the WalletConnect confirmation dialog under the label "Total Amount with Royalties": [3](#0-2) 

### Impact Explanation

A user approving a WalletConnect `take_offer` request that involves multiple royalty-bearing NFTs is shown a "Total Amount with Royalties" figure that is lower than the amount the blockchain will actually deduct. The discrepancy grows with the number of NFTs and the magnitude of their royalty percentages. The user makes an approval decision based on a materially incorrect spending total, resulting in more XCH or CAT being spent than they consented to.

This matches the allowed High impact: *"Corruption … of … WalletConnect state that causes a user to approve … the wrong … amount."*

### Likelihood Explanation

Any WalletConnect-connected dApp can present a `take_offer` payload containing two or more NFTs with non-zero royalties. No special privileges are required; the attacker only needs to craft such an offer and share it. The victim's wallet will display the understated total and, if approved, the on-chain royalty enforcement will deduct the correct (higher) amount.

### Recommendation

Remove the `splitAmount` division. Apply each royalty percentage to the full `amount`:

```ts
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [4](#0-3) 

Update the corresponding test expectation in `parseCommandDisplay.test.ts` to reflect the corrected value (`0.0001051` instead of `0.00010255`).

### Proof of Concept

1. Attacker creates an offer: offer 2 NFTs (NFT-A with 5% royalty, NFT-B with 10% royalty) in exchange for 0.0001 XCH.
2. Attacker shares the offer string with a victim via a WalletConnect-connected dApp.
3. Victim's wallet calls `parseCommandDisplay('chia_wallet.take_offer', { offer: '...' })`.
4. `formatAmountWithRoyalties` is invoked with `amount = 100_000_000n` and `royaltyPercentages = [500, 1000]`.
5. `splitAmount = 100_000_000n / 2n = 50_000_000n`.
6. Displayed total: `100_000_000 + (50_000_000×500/10_000) + (50_000_000×1000/10_000) = 107_500_000` mojos ≈ 0.0001075 XCH.
7. Correct total: `100_000_000 + (100_000_000×500/10_000) + (100_000_000×1000/10_000) = 115_000_000` mojos = 0.000115 XCH.
8. Victim sees ~0.0001075 XCH and approves; blockchain deducts 0.000115 XCH — a ~7% understatement in this example, scaling with royalty magnitudes and NFT count. [1](#0-0)

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
