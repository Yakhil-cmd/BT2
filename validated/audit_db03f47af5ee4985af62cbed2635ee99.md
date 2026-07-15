### Title
WalletConnect Royalty Total Understated by Factor of N When Multiple NFTs Are Offered — (`File: packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary

The `formatAmountWithRoyalties` function in the WalletConnect command-display pipeline contains an arithmetic error: when an offer involves N NFTs on the opposite side, it divides the fungible amount by N before applying each royalty percentage, producing a displayed "Total Amount with Royalties" that is N times smaller than the actual on-chain cost. A malicious dApp connected via WalletConnect can exploit this to make the user approve a `take_offer` transaction whose true cost is materially higher than what the confirmation dialog shows.

### Finding Description

`formatAmountWithRoyalties` is called from `withRoyaltyTotals` to compute the `amountWithRoyalties` field shown in the WalletConnect `Confirm` dialog:

```typescript
// parseCommandDisplay.ts lines 354-375
function formatAmountWithRoyalties(line, amount, royaltyPercentages) {
  const splitAmount = amount / BigInt(royaltyPercentages.length); // ← divides by N
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) =>
      total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
  ...
}
``` [1](#0-0) 

The correct formula for total royalties across N NFTs is:

```
total_royalty = amount × Σ(royalty_i) / 10_000
```

The implemented formula computes:

```
total_royalty = (amount / N) × Σ(royalty_i) / 10_000
```

This is exactly **N times too small**. The existing test suite confirms the wrong value is accepted as correct: [2](#0-1) 

With two NFTs carrying royalties of 500 (5 %) and 10 (0.1 %) and a base amount of 0.0001 XCH, the test expects `amountWithRoyalties = '0.00010255'`. The mathematically correct value is `0.0001051` — the displayed figure is ~50 % of the true royalty burden.

The `amountWithRoyalties` field is rendered in the WalletConnect confirmation dialog under the label **"Total Amount with Royalties"**: [3](#0-2) 

The royalty percentages for `take_offer` are extracted from the offer summary's `infos` field without any cap or cross-check against on-chain NFT state: [4](#0-3) 

For `create_offer_for_ids`, they come directly from the dApp-supplied `driver_dict`: [5](#0-4) 

### Impact Explanation

A malicious dApp that has an active WalletConnect session sends `chia_wallet.take_offer` with a crafted offer containing multiple NFTs with high royalty percentages. The confirmation dialog shows a "Total Amount with Royalties" that is N times lower than the actual spend. The user approves believing the cost is acceptable; the wallet executes the transaction and the user pays the true (much higher) royalty-inclusive amount. With 5 NFTs each carrying a 10 % royalty and a 1 XCH base price, the dialog shows 1.1 XCH while the actual spend is 1.5 XCH — a 36 % understatement.

This satisfies the **High** impact criterion: *"Corruption, spoofing, or unsafe trust of … WalletConnect state that causes a user to approve … the wrong … amount."*

### Likelihood Explanation

Any dApp that has obtained a WalletConnect pairing (a normal user action) and has been granted the `chia_wallet.take_offer` command can trigger this. No additional privileges, leaked keys, or cryptographic breaks are required. The bug is deterministic and reproducible for any offer with two or more NFTs on the offered side.

### Recommendation

Replace the split-then-sum formula with the correct per-NFT calculation:

```typescript
// Correct: apply each royalty to the full amount
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) =>
    total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [6](#0-5) 

Additionally, add a test that verifies the displayed total equals `base + base × Σ(royalty_i / 10_000)` for multi-NFT offers.

### Proof of Concept

1. Attacker dApp connects to victim wallet via WalletConnect and is granted `chia_wallet.take_offer`.
2. Attacker crafts an offer string whose `get_offer_summary` response contains:
   - `offered`: 5 NFT launcher IDs, each with `royalty_percentage: 1000` (10 %) in `infos`
   - `requested`: `{ xch: '1000000000000' }` (1 XCH)
3. Attacker sends `chia_wallet.take_offer` via WalletConnect.
4. `parseCommandDisplay` calls `formatAmountWithRoyalties(line, 1_000_000_000_000n, [1000,1000,1000,1000,1000])`.
5. `splitAmount = 1_000_000_000_000n / 5n = 200_000_000_000n`
6. `royaltyAmount = 5 × (200_000_000_000 × 1000 / 10_000) = 5 × 20_000_000_000 = 100_000_000_000` mojos
7. Dialog shows **"Total Amount with Royalties: 1.1 XCH"**.
8. Correct value: `5 × (1_000_000_000_000 × 1000 / 10_000) = 500_000_000_000` mojos → **1.5 XCH**.
9. User approves at 1.1 XCH; wallet spends 1.5 XCH. [7](#0-6)

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L184-206)
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
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L239-261)
```typescript
function createOfferRoyaltyPercentages(
  walletDelta: WalletDelta,
  driverDict: Record<string, unknown>,
): AssetRoyaltyPercentages {
  const royaltyPercentages: AssetRoyaltyPercentages = {
    spending: {},
    receiving: {},
  };

  for (const assetId of Object.keys(walletDelta.spending)) {
    royaltyPercentages.spending[assetId] = royaltyPercentageForDriverInfo(
      driverDict[assetId] ?? driverDict[`0x${assetId}`],
    );
  }

  for (const assetId of Object.keys(walletDelta.receiving)) {
    royaltyPercentages.receiving[assetId] = royaltyPercentageForDriverInfo(
      driverDict[assetId] ?? driverDict[`0x${assetId}`],
    );
  }

  return royaltyPercentages;
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L354-394)
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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L19-29)
```typescript
export type DisplayWalletDeltaItem =
  | { kind: 'xch'; amount: string; amountWithRoyalties?: string }
  | { kind: 'wallet'; walletId: string; amount: string; walletName?: string; amountWithRoyalties?: string }
  | { kind: 'cat'; amount: string; assetId: string; symbol?: string; amountWithRoyalties?: string }
  | { kind: 'nft'; nftId: string; name?: string; previewUrl?: string; royaltyPercentage?: number };

export type DisplayWalletDelta = {
  spending: DisplayWalletDeltaItem[];
  receiving: DisplayWalletDeltaItem[];
  fee?: string;
};
```
