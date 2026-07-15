### Title
WalletConnect Offer Confirmation Understates Total XCH Spend When Multiple NFTs With Royalties Are Present - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in the WalletConnect command display pipeline incorrectly divides the base XCH amount by the number of NFTs before computing each royalty, causing the `amountWithRoyalties` figure shown in the WalletConnect confirmation dialog to be substantially understated whenever a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request involves two or more NFTs with royalties. A user who approves based on the displayed total will actually spend more XCH than they were shown.

### Finding Description
`formatAmountWithRoyalties` computes the royalty surcharge as follows:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by NFT count
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

Each NFT's royalty should be applied to the **full** `amount`, not to `amount / N`. The correct formula is:

```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

The current formula instead computes:

```
royaltyAmount = Σ ((amount / N) × royaltyPercentage_i / 10_000)
```

which is `1/N` of the correct value. The `royaltyPercentages` array is built by `royaltyPercentagesForSide`, which collects every NFT royalty on the opposite trade side: [2](#0-1) 

`withRoyaltyTotals` then calls `formatAmountWithRoyalties` for every fungible (XCH/CAT) line on the spending side: [3](#0-2) 

This display value is surfaced to the user inside the WalletConnect confirmation dialog before they approve `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids`: [4](#0-3) 

### Impact Explanation
A malicious dApp connected via WalletConnect presents an offer containing two or more NFTs with non-trivial royalties. The confirmation dialog shows an `amountWithRoyalties` that is `1/N` of the correct royalty surcharge. The user approves believing they will spend, say, 1.5 XCH, but the blockchain correctly applies the full royalties and debits 2 XCH. The discrepancy scales with both the number of NFTs and their royalty percentages. This constitutes spoofing of WalletConnect state that causes a user to approve the wrong amount — a High-severity impact under the allowed scope.

### Likelihood Explanation
Any WalletConnect-connected dApp can craft a `take_offer` or `create_offer_for_ids` request referencing two or more NFTs with royalties. No special privileges, leaked keys, or social engineering beyond the normal WalletConnect pairing flow are required. The existing test suite even exercises the multi-NFT royalty path and encodes the incorrect (understated) value as the expected result, confirming the bug is present in production code: [5](#0-4) 

### Recommendation
Remove the `splitAmount` division. Each NFT royalty must be applied to the full `amount`:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test expectations to reflect the corrected totals.

### Proof of Concept
Offer summary sent via WalletConnect:
- `requested.xch = 100_000_000` mojos (0.0001 XCH)
- NFT A: `royalty_percentage = 500` (5 %)
- NFT B: `royalty_percentage = 10` (0.1 %)

**Current (buggy) display:**
- `splitAmount = 100_000_000 / 2 = 50_000_000`
- royalty A = `50_000_000 × 500 / 10_000 = 2_500_000`
- royalty B = `50_000_000 × 10 / 10_000 = 50_000`
- shown total = `102_550_000` mojos → **0.00010255 XCH**

**Correct calculation:**
- royalty A = `100_000_000 × 500 / 10_000 = 5_000_000`
- royalty B = `100_000_000 × 10 / 10_000 = 100_000`
- correct total = `105_100_000` mojos → **0.0001051 XCH**

The user approves seeing 0.00010255 XCH but the blockchain debits 0.0001051 XCH — a ~2.5 % understatement in this example, growing proportionally with royalty rates and NFT count. [6](#0-5)

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L345-352)
```typescript
function royaltyPercentagesForSide(lines: DisplayWalletDeltaItem[]): number[] {
  return lines
    .filter((line): line is Extract<DisplayWalletDeltaItem, { kind: 'nft' }> => line.kind === 'nft')
    .map((line) => line.royaltyPercentage)
    .filter(
      (royaltyPercentage): royaltyPercentage is number => royaltyPercentage !== undefined && royaltyPercentage > 0,
    );
}
```

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
