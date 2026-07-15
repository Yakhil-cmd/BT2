### Title
Incorrect Multi-NFT Royalty Amount Displayed in WalletConnect `take_offer` Confirmation Dialog - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in the WalletConnect command display pipeline incorrectly calculates the total fungible amount (including royalties) when a `take_offer` involves multiple NFTs. It divides the payment amount equally among NFTs before computing each NFT's royalty, rather than applying each NFT's royalty percentage to the full payment amount. The result is that the `amountWithRoyalties` shown in the WalletConnect confirmation dialog is materially lower than what the blockchain will actually deduct, causing users to approve transactions under a false understanding of the true cost.

### Finding Description

In `parseCommandDisplay.ts`, the function `formatAmountWithRoyalties` computes the displayed total cost including royalties:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The `splitAmount` divides the fungible payment by the number of NFTs before multiplying by each royalty percentage. In the Chia protocol, each NFT's royalty puzzle independently claims its percentage of the **full** payment amount — not a fractional share. The correct formula is:

```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

The code computes instead:

```
royaltyAmount = Σ ((amount / N) × royaltyPercentage_i / 10_000)
```

This underestimates total royalties by a factor of N (number of NFTs).

The `formatAmountWithRoyalties` result is surfaced as `amountWithRoyalties` on the spending line of the WalletConnect confirmation dialog for both `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`. [2](#0-1) 

The existing test fixture confirms the split behavior is baked in:

```
amount = 100_000_000 mojos (0.0001 XCH)
NFT1 royalty = 500 (5%), NFT2 royalty = 10 (0.1%)
Expected amountWithRoyalties = '0.00010255'   ← split result
Correct amountWithRoyalties  = '0.0001051'    ← full-amount result
``` [3](#0-2) 

### Impact Explanation

A WalletConnect-connected dApp can craft a `take_offer` payload containing multiple NFTs with high royalty percentages. The confirmation dialog will display a materially understated total cost. For example, with 2 NFTs each carrying a 50% royalty on a 10 XCH payment:

- **Displayed**: 10 + 5 = **15 XCH** (split: each NFT sees 5 XCH base)
- **Actual deducted**: 10 + 10 = **20 XCH** (each NFT royalty on full 10 XCH)

The user approves believing they spend 15 XCH; the blockchain deducts 20 XCH. This satisfies the High impact criterion: WalletConnect state causes a user to approve the wrong amount.

### Likelihood Explanation

Any WalletConnect-paired dApp can issue a `take_offer` command. The attacker only needs to construct an offer with ≥2 NFTs bearing non-trivial royalties — a normal, permissionless operation. The victim must have WalletConnect enabled and paired with the attacker's dApp, which is the standard WalletConnect threat model. The discrepancy grows linearly with the number of NFTs and the royalty percentages, making it exploitable at realistic royalty levels (5–50%).

### Recommendation

Replace the split-then-multiply formula with the correct per-NFT full-amount calculation:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Remove the `splitAmount` intermediate variable entirely.

### Proof of Concept

**Setup**: Attacker mints NFT-A (royalty 5000 = 50%) and NFT-B (royalty 5000 = 50%). Attacker creates an offer: give NFT-A + NFT-B, receive 10 XCH. Attacker sends the offer string to a victim via a WalletConnect-paired dApp using `chia_wallet.take_offer`.

**Victim's confirmation dialog** (via `parseCommandDisplay` → `formatAmountWithRoyalties`):

```
splitAmount = 10_000_000_000_000 / 2 = 5_000_000_000_000
royaltyAmount = (5e12 * 5000 / 10000) + (5e12 * 5000 / 10000)
              = 2_500_000_000_000 + 2_500_000_000_000 = 5_000_000_000_000
amountWithRoyalties displayed = 15 XCH
```

**Actual blockchain deduction**:

```
royaltyAmount = (10e12 * 5000 / 10000) + (10e12 * 5000 / 10000)
              = 5_000_000_000_000 + 5_000_000_000_000 = 10_000_000_000_000
actual total = 20 XCH
```

The victim approves 15 XCH but 20 XCH is deducted — a 33% overcharge relative to what was displayed. [4](#0-3) [5](#0-4)

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
