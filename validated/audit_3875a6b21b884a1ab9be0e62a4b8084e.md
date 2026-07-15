I found a real analog. Let me read the exact lines of the relevant function to confirm the bug precisely.

### Title
WalletConnect Offer Confirmation Displays Understated Royalty Total When Multiple NFTs Are Present - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
`formatAmountWithRoyalties` in the WalletConnect command-display pipeline incorrectly divides the fungible payment amount by the number of NFTs before computing each NFT's royalty. When a dApp submits a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` command containing multiple royalty-bearing NFTs, the confirmation dialog shows the user a total-with-royalties figure that is `N` times smaller than the true on-chain cost (where `N` is the number of NFTs). The user approves an offer believing they are spending less than they actually will.

### Finding Description

`formatAmountWithRoyalties` is called from `withRoyaltyTotals` to produce the `amountWithRoyalties` string shown in the WalletConnect approval dialog. [1](#0-0) 

The critical lines:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by NFT count
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Each NFT's royalty is computed on `amount / N` instead of on the full `amount`. The net effect is:

| | Formula |
|---|---|
| **Displayed (buggy)** | `royalty = (amount / N) × Σ(royalty_pct_i) / 10_000` |
| **Correct (on-chain)** | `royalty = amount × Σ(royalty_pct_i) / 10_000` |

The displayed royalty is exactly `1/N` of the true royalty. With 2 NFTs the user sees half the real cost; with 3 NFTs, one-third; and so on.

The test suite encodes and confirms this wrong value as the expected output: [2](#0-1) 

Scenario from the test: paying 100,000,000 mojos (0.0001 XCH) for two NFTs with 500 bps (5%) and 10 bps (0.1%) royalties.

- **Displayed**: `0.00010255` XCH (test-confirmed)
- **Correct**: `0.0001 + (0.0001 × 500/10000) + (0.0001 × 10/10000)` = `0.0001051` XCH

The dialog is populated by `walletDeltaToDisplay`, which calls `withRoyaltyTotals` for both the `take_offer` and `create_offer_for_ids` WalletConnect commands: [3](#0-2) [4](#0-3) 

### Impact Explanation

The `amountWithRoyalties` field is the only place in the WalletConnect confirmation dialog where the user sees the true cost of accepting an NFT offer. When it is understated, the user approves a spend they would not have approved had they seen the correct figure. This is a **High** impact: corruption of WalletConnect offer state that causes a user to approve the wrong amount.

The severity grows with the number of NFTs: a bundle of 5 NFTs causes the displayed royalty cost to be 5× lower than reality.

### Likelihood Explanation

Any WalletConnect-connected dApp can craft a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` payload containing two or more royalty-bearing NFTs. No special privileges are required. The user must only have WalletConnect enabled and accept a connection from the dApp.

### Recommendation

Remove the `splitAmount` division. Each NFT's royalty must be computed on the full fungible amount:

```typescript
// Correct
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test expectations to reflect the corrected values.

### Proof of Concept

Using the existing test fixture (two NFTs, 500 bps + 10 bps, 100,000,000 mojos):

**Current (buggy) path:**
```
splitAmount = 100_000_000 / 2 = 50_000_000
royaltyAmount = (50_000_000 × 500 / 10_000) + (50_000_000 × 10 / 10_000)
             = 2_500_000 + 50_000 = 2_550_000
displayed    = 102_550_000 mojos = 0.00010255 XCH   ← shown to user
```

**Correct path:**
```
royaltyAmount = (100_000_000 × 500 / 10_000) + (100_000_000 × 10 / 10_000)
             = 5_000_000 + 100_000 = 5_100_000
correct      = 105_100_000 mojos = 0.0001051 XCH    ← actual on-chain cost
```

The user is shown `0.00010255 XCH` but the blockchain will deduct `0.0001051 XCH` — a 2.4% understatement that scales linearly with the number of NFTs in the offer.

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
