### Title
WalletConnect Multi-NFT Royalty Accounting Underestimates Total Spend in Approval Dialog - (`File: packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

`formatAmountWithRoyalties` in `parseCommandDisplay.ts` incorrectly divides the fungible payment amount equally among all receiving NFTs before computing each NFT's royalty, instead of applying each royalty percentage to the full amount. When a WalletConnect dApp sends a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` command involving multiple NFTs with royalties, the "Total Amount with Royalties" shown in the Electron confirmation dialog (`Confirm.tsx`) is materially understated. A user who approves based on the displayed figure will have more XCH or CAT deducted from their wallet than they consented to.

### Finding Description

`formatAmountWithRoyalties` is called during WalletConnect command parsing for `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`. Its purpose is to compute the total fungible cost including all NFT creator royalties, so the user can see the true spend before approving.

The buggy logic:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts, lines 363-367
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by NFT count
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Each NFT's royalty is computed on `splitAmount = amount / N` rather than on the full `amount`. The correct formula is:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

**Concrete example (confirmed by the existing test at line 251):**

| | Buggy (displayed) | Correct (actual on-chain) |
|---|---|---|
| Payment | 0.0001 XCH | 0.0001 XCH |
| NFT1 royalty (5%) | 0.5 × 5% = 0.0000025 | 1 × 5% = 0.000005 |
| NFT2 royalty (0.1%) | 0.5 × 0.1% = 0.0000000005 | 1 × 0.1% = 0.000001 |
| **Total shown** | **0.00010255 XCH** | **0.0001051 XCH** |

The test at line 310–334 asserts `amountWithRoyalties: '0.00010255'`, which is the wrong value — it encodes the bug as expected behavior. [1](#0-0) 

The computed `amountWithRoyalties` string is attached to the `DisplayWalletDeltaItem` and rendered in the WalletConnect confirmation dialog under the label "Total Amount with Royalties": [2](#0-1) 

The dialog strings confirm this field is shown to the user before they click "Accept": [3](#0-2) 

### Impact Explanation

A user approving a WalletConnect `take_offer` or `create_offer_for_ids` command for a bundle of N ≥ 2 NFTs with royalties sees a "Total Amount with Royalties" that is understated by approximately `(N-1)/N × Σ(royalty_i)`. The actual on-chain transaction deducts the correct (higher) royalty amount. The user has approved a spend they did not consent to at the displayed figure. This is a direct, concrete asset loss triggered by approving a WalletConnect command — matching the High impact criterion: *"WalletConnect state that causes a user to approve the wrong amount."* [4](#0-3) 

### Likelihood Explanation

Any WalletConnect-connected dApp can send a `take_offer` command containing a crafted offer with two or more NFTs that carry royalties. The attacker mints NFTs with high royalty percentages (up to the protocol maximum), bundles them into a single offer, and presents it to the user. The user's approval dialog shows a lower total than what will be spent. No special privileges, leaked keys, or social engineering beyond the standard WalletConnect pairing are required. [5](#0-4) 

### Recommendation

Replace the split-then-sum pattern with a full-amount-per-NFT sum:

```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  // Each NFT's royalty is computed on the full fungible amount, not a split share.
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

Update the corresponding test assertion at line 320 from `'0.00010255'` to `'0.0001051'`. [1](#0-0) 

### Proof of Concept

1. Attacker mints two NFTs: NFT-A (10% royalty, 1000 basis points) and NFT-B (10% royalty, 1000 basis points).
2. Attacker creates an offer: sell NFT-A + NFT-B, request 10 XCH.
3. Attacker connects to victim's wallet via WalletConnect and sends `chia_wallet.take_offer` with the offer string.
4. Victim's GUI calls `parseCommandDisplay` → `formatAmountWithRoyalties`:
   - `splitAmount = 10_000_000_000_000 / 2 = 5_000_000_000_000` mojos
   - royalty per NFT = `5_000_000_000_000 × 1000 / 10_000 = 500_000_000_000` mojos
   - total royalties = `1_000_000_000_000` mojos = 1 XCH
   - **Displayed total: 11 XCH**
5. Correct on-chain royalties:
   - NFT-A: `10_000_000_000_000 × 1000 / 10_000 = 1_000_000_000_000` mojos
   - NFT-B: same = `1_000_000_000_000` mojos
   - total royalties = `2_000_000_000_000` mojos = 2 XCH
   - **Actual spend: 12 XCH**
6. Victim sees "Total Amount with Royalties: 11 XCH", approves, and 12 XCH is deducted — 1 XCH more than consented to. [1](#0-0) [6](#0-5)

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L251-335)
```typescript
  it('shows the take-offer fungible total with multiple NFT creator royalties', async () => {
    const firstNftLauncherId = '0fbdbe7e1392f248f4ce3f8b1497496f056db6eb3856990ea3f697e28ec082c4';
    const secondNftLauncherId = '022a8c5c7c111111111111111111111111111111111111111111111111111111';
    mockGetWalletInfos.mockResolvedValue({});
    mockGetOfferSummary.mockResolvedValue(
      makeOfferSummary({
        offered: {
          [firstNftLauncherId]: '1',
          [secondNftLauncherId]: '1',
        },
        requested: {
          xch: '100000000',
        },
        infos: {
          [firstNftLauncherId]: {
            type: 'singleton',
            also: {
              type: 'metadata',
              also: {
                type: 'ownership',
                transfer_program: {
                  type: 'royalty transfer program',
                  royalty_percentage: '500',
                },
              },
            },
          },
          [secondNftLauncherId]: {
            type: 'singleton',
            also: {
              type: 'metadata',
              also: {
                type: 'ownership',
                transfer_program: {
                  type: 'royalty transfer program',
                  royalty_percentage: '10',
                },
              },
            },
          },
        },
      }),
    );
    mockNftGetInfo
      .mockResolvedValueOnce({
        success: true,
        nft_info: {
          data_uris: [],
          royalty_percentage: 500,
        },
      })
      .mockResolvedValueOnce({
        success: true,
        nft_info: {
          data_uris: [],
          royalty_percentage: 10,
        },
      });

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
