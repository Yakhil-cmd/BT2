### Title
Incorrect Multi-NFT Royalty Amount Displayed in WalletConnect Offer Approval Dialog, Causing Users to Approve Understated Spend Amounts - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly calculates the total fungible amount (including royalties) shown to users in the WalletConnect `chia_wallet.take_offer` confirmation dialog when multiple NFTs are involved. The function divides the fungible payment amount equally among all NFTs before applying each NFT's royalty percentage, producing a dramatically understated `amountWithRoyalties` display. A malicious dApp can exploit this to trick a user into approving an offer whose true cost is a multiple of what the confirmation dialog shows.

### Finding Description

In `formatAmountWithRoyalties`:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts
const splitAmount = amount / BigInt(royaltyPercentages.length);   // BUG: divides first
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The correct formula is to apply each NFT's royalty percentage to the **full** fungible amount, then sum the royalties. Instead, the code first splits the amount equally across all NFTs, then applies each royalty to the split portion. This is mathematically equivalent to dividing the total royalty by the number of NFTs.

**Concrete example** (matching the existing test at line 251):

| | Displayed (buggy) | Correct |
|---|---|---|
| Amount | 100,000,000 mojos | 100,000,000 mojos |
| NFT1 royalty (5%) | 50,000,000 × 500 / 10,000 = 2,500,000 | 100,000,000 × 500 / 10,000 = 5,000,000 |
| NFT2 royalty (0.1%) | 50,000,000 × 10 / 10,000 = 50,000 | 100,000,000 × 10 / 10,000 = 100,000 |
| Total shown | 102,550,000 mojos | 105,100,000 mojos |

The discrepancy scales with the number of NFTs. With 10 NFTs each carrying a 50% royalty and a 1 XCH payment, the dialog shows **1.5 XCH** while the user actually pays **6 XCH** — a 4× understatement.

The `amountWithRoyalties` field is produced by `walletDeltaToDisplay` → `withRoyaltyTotals` → `formatAmountWithRoyalties`, and is returned by `parseCommandDisplay` exclusively for the WalletConnect command display path (`chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`). [2](#0-1) [3](#0-2) 

### Impact Explanation

When a dApp sends a `chia_wallet.take_offer` WalletConnect command, the GUI presents the user with a confirmation dialog that includes `amountWithRoyalties` — the total XCH or CAT the user will spend, including creator royalties. Because this value is understated (sometimes by a large multiple), the user approves the offer believing they are committing to a lower spend than the blockchain will actually enforce. The blockchain enforces the correct royalties regardless of what the dialog shows, so the user's wallet is debited the true (higher) amount after approval.

This satisfies the **High** impact criterion: WalletConnect state causes a user to approve the wrong amount.

### Likelihood Explanation

The attack requires a dApp to:
1. Construct an offer containing two or more NFTs with non-trivial royalty percentages.
2. Send a `chia_wallet.take_offer` WalletConnect command to the victim's wallet.

No leaked keys, host compromise, or cryptographic break is needed. Any WalletConnect-connected dApp can craft such an offer. The discrepancy grows with the number of NFTs and the magnitude of royalty percentages, making it straightforward to engineer a scenario where the displayed cost is a small fraction of the true cost.

### Recommendation

Replace the split-then-apply logic with apply-then-sum:

```typescript
// Correct: apply each royalty to the full amount
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

Add a unit test covering the multi-NFT case that asserts `amountWithRoyalties` equals the sum of the base amount plus each NFT's royalty applied to the full base amount.

### Proof of Concept

The existing test at line 251 of `parseCommandDisplay.test.ts` inadvertently documents the bug: it asserts `amountWithRoyalties: '0.00010255'` for a 2-NFT offer with royalties of 500 and 10 basis points on 100,000,000 mojos. [4](#0-3) 

The correct value is `0.0001051` (5,000,000 + 100,000 = 5,100,000 mojos in royalties, total 105,100,000 mojos). The test passes today only because it encodes the buggy expected value. A corrected implementation would fail this test, confirming the discrepancy.

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
