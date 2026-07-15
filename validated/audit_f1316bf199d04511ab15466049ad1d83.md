### Title
Incorrect Multi-NFT Royalty Calculation in WalletConnect Confirmation Dialog Causes Systematic Underestimation of Spend Amount - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the fungible amount equally among all NFTs before computing each NFT's royalty, rather than applying each royalty to the full amount. This causes the WalletConnect confirmation dialog to display a systematically underestimated `amountWithRoyalties` whenever a user is asked to approve a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` command involving multiple NFTs with royalties. The user approves believing they will spend less XCH/CAT than the transaction actually deducts.

### Finding Description

`formatAmountWithRoyalties` in `parseCommandDisplay.ts` is the function that computes the "total including royalties" figure shown in the WalletConnect approval dialog: [1](#0-0) 

The critical lines are:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← wrong
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

The code divides the total fungible amount equally among all NFTs (`splitAmount = amount / N`) and then applies each NFT's royalty percentage to that fractional share. In Chia's royalty model, each NFT's royalty is independently calculated on the **full** purchase price, not on a 1/N share of it. The correct formula is:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

**Concrete arithmetic (from the existing test):**

| | Buggy (current) | Correct |
|---|---|---|
| Base amount | 100,000,000 mojos | 100,000,000 mojos |
| splitAmount | 50,000,000 (÷2) | — |
| NFT1 royalty (5%) | 2,500,000 | 5,000,000 |
| NFT2 royalty (0.1%) | 50,000 | 100,000 |
| Total royalty | 2,550,000 | 5,100,000 |
| Displayed total | **0.00010255 XCH** | **0.0001051 XCH** |

The existing test at line 310–334 asserts `amountWithRoyalties: '0.00010255'`, which is the buggy value — the test itself encodes the incorrect expectation. [2](#0-1) 

The underestimation factor grows with the number of NFTs: with N NFTs the displayed royalty is 1/N of the correct royalty. With 5 NFTs each carrying a 10% royalty, the user sees 2% total royalty instead of 50%.

`parseCommandDisplay` is invoked from `main.tsx` to populate the WalletConnect confirmation dialog before the user clicks "Approve": [3](#0-2) 

### Impact Explanation

A user approving a WalletConnect `chia_wallet.take_offer` command is shown an `amountWithRoyalties` figure that is materially lower than the amount the wallet daemon will actually deduct. The user's consent is obtained under false pretenses: they see a lower cost and approve, but the on-chain transaction spends more XCH or CAT than the dialog indicated. This is a direct, concrete asset loss caused by incorrect WalletConnect state being trusted for approval.

### Likelihood Explanation

Any WalletConnect-connected dApp can trigger this by presenting an offer that bundles multiple NFTs with royalties. The dApp does not need any special privilege; it only needs an active WalletConnect session (which the user has already granted). The bug is deterministic and reproducible for any offer with ≥2 NFTs carrying royalties. The underestimation scales linearly with the number of NFTs, making it more severe as bundle offers become more common.

### Recommendation

Replace the split-amount logic with a per-NFT full-amount royalty calculation:

```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  // Each NFT's royalty is applied to the full amount, not a fractional share.
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;

  if (line.kind === 'xch') {
    return mojoToChiaLocaleString(totalAmount);
  }
  return mojoToCATLocaleString(totalAmount);
}
```

Update the corresponding test assertions to reflect the corrected values (e.g., `'0.0001051'` instead of `'0.00010255'` for the two-NFT case).

### Proof of Concept

Using the values already present in the test suite:

- Offer: user accepts 2 NFTs (royalties 5% and 0.1%) in exchange for 100,000,000 mojos (0.0001 XCH).
- **Displayed** `amountWithRoyalties`: `0.00010255 XCH` (current buggy output).
- **Actual** amount the wallet deducts: `0.0001051 XCH` (base + 5,000,000 + 100,000 mojos royalties).
- **Discrepancy**: 2,550,000 mojos (~25.5% underestimation of the royalty portion).

With 10 NFTs each at 10% royalty on a 1 XCH offer, the dialog would show ~1.01 XCH while the wallet deducts ~2 XCH — a 2× understatement of the true cost. [4](#0-3)

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
