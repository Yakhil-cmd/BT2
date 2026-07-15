### Title
Understated `amountWithRoyalties` in WalletConnect `take_offer` Approval Dialog Due to Incorrect Royalty Split Divisor — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
`formatAmountWithRoyalties` divides the fungible spend amount by the number of NFTs before applying each NFT's royalty percentage. When a WalletConnect `chia_wallet.take_offer` command involves multiple NFTs with differing royalty percentages, the displayed `amountWithRoyalties` shown to the user before approval is materially understated relative to what the blockchain will actually deduct.

### Finding Description
In `parseCommandDisplay.ts`, `formatAmountWithRoyalties` (lines 363–368) computes:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← wrong divisor
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

Each NFT's royalty is supposed to be calculated on the **full** fungible amount, because every NFT independently claims its royalty from the full purchase price. Instead, the code first divides `amount` by the count of NFTs (`royaltyPercentages.length`) and applies each percentage to that reduced `splitAmount`. This is the same class of bug as the Solarray report: the wrong dimension (NFT count) is used as the loop/calculation bound, causing the summation to be short by a factor proportional to the number of NFTs.

The existing test at lines 251–335 of `parseCommandDisplay.test.ts` encodes and asserts the **wrong** value, confirming the bug is present and untested-against-correct-behavior:

- Two NFTs: royalty_percentage `500` (5 %) and `10` (0.1 %)
- XCH amount: 100 000 000 mojos (0.0001 XCH)
- **Displayed** `amountWithRoyalties`: `0.00010255` XCH
- **Correct** `amountWithRoyalties`: `0.0001051` XCH [2](#0-1) 

Arithmetic:

| | Current (wrong) | Correct |
|---|---|---|
| splitAmount | 50 000 000 | — |
| NFT-1 royalty (5 %) | 2 500 000 | 5 000 000 |
| NFT-2 royalty (0.1 %) | 50 000 | 100 000 |
| Total royalty | 2 550 000 | 5 100 000 |
| `amountWithRoyalties` | 102 550 000 mojos | 105 100 000 mojos |

The discrepancy scales with both the number of NFTs and the spread between their royalty percentages. With two NFTs carrying 10 % and 20 % royalties on 1 XCH, the displayed total would be 1.15 XCH while the actual spend is 1.30 XCH — a 0.15 XCH understatement.

### Impact Explanation
`parseCommandDisplay` is the sole source of the wallet-delta display rendered in the WalletConnect approval dialog before the user signs a `chia_wallet.take_offer` transaction. [3](#0-2) 

The `amountWithRoyalties` field is the only figure shown to the user that represents the **total** XCH they will spend including creator royalties. Because it is understated, a user reviewing the approval dialog sees a lower total than what the blockchain will actually deduct from their wallet. This causes the user to approve a `take_offer` transaction under a false understanding of the true cost, satisfying the High-impact criterion: WalletConnect state causes a user to approve the wrong amount.

### Likelihood Explanation
Any unprivileged party can create a valid Chia offer that bundles two or more NFTs with distinct royalty percentages and deliver it to a victim via WalletConnect. No leaked keys, host compromise, or social engineering beyond the normal WalletConnect pairing flow is required. The victim's approval dialog will silently display the understated total. The bug is triggered whenever `royaltyPercentages.length > 1` and the percentages are not all equal.

### Recommendation
Remove the `splitAmount` division. Each NFT's royalty must be computed against the full fungible `amount`:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test assertion in `parseCommandDisplay.test.ts` to expect `0.0001051` instead of `0.00010255`.

### Proof of Concept

1. Attacker creates a Chia offer: offers two NFTs (NFT-A with 5 % royalty, NFT-B with 10 % royalty) in exchange for 1 XCH.
2. Attacker delivers the offer string to the victim's wallet via a WalletConnect `chia_wallet.take_offer` request.
3. The victim's GUI calls `parseCommandDisplay('chia_wallet.take_offer', { offer: '...' })`.
4. `offerSummaryRoyaltyPercentages` extracts `[500, 1000]` from the offer's `infos` dict. [4](#0-3) 
5. `formatAmountWithRoyalties` computes `splitAmount = 1_000_000_000_000n / 2n = 500_000_000_000n`, then royalty = `(500_000_000_000 × 500 / 10000) + (500_000_000_000 × 1000 / 10000)` = 25 000 000 000 + 50 000 000 000 = 75 000 000 000 mojos → displayed total **1.075 XCH**. [1](#0-0) 
6. Correct total: (1 × 5 %) + (1 × 10 %) = 0.15 XCH royalties → **1.15 XCH**.
7. The approval dialog shows **1.075 XCH**; the blockchain deducts **1.15 XCH** — a 0.075 XCH shortfall the user never consented to.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L184-205)
```typescript
function offerSummaryRoyaltyPercentages(offerSummary: OfferSummaryForDisplay): AssetRoyaltyPercentages {
  const royaltyPercentages: AssetRoyaltyPercentages = {
    spending: {},
    receiving: {},
  };

  const { infos } = offerSummary;
  if (!isPlainObject(infos)) {
    return royaltyPercentages;
  }

  for (const assetId of Object.keys(offerSummary.requested)) {
    const parsedAssetId = assetId === 'xch' ? '1' : assetId;
    royaltyPercentages.spending[parsedAssetId] = royaltyPercentageForDriverInfo(infos[assetId]);
  }

  for (const assetId of Object.keys(offerSummary.offered)) {
    const parsedAssetId = assetId === 'xch' ? '1' : assetId;
    royaltyPercentages.receiving[parsedAssetId] = royaltyPercentageForDriverInfo(infos[assetId]);
  }

  return royaltyPercentages;
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L363-368)
```typescript
  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L438-459)
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
