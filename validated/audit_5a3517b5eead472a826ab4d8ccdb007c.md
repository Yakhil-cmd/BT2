### Title
Incorrect Multi-NFT Royalty Amount Displayed in WalletConnect Offer Confirmation — (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the fungible amount by the number of NFTs before applying each NFT's royalty percentage. When a WalletConnect offer involves multiple NFTs with royalties, the displayed `amountWithRoyalties` shown in the approval dialog is understated by a factor of N (the number of NFTs), causing the user to approve a transaction believing they will spend less than they actually will.

### Finding Description

In `formatAmountWithRoyalties`, the royalty calculation is:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);  // BUG: divides by N
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The `splitAmount` divides the full fungible amount by the count of NFTs before multiplying by each royalty percentage. This means the total royalty computed is:

```
royaltyAmount = (amount/N * r1/10000) + (amount/N * r2/10000) + ...
              = amount * (r1 + r2 + ... + rN) / (N * 10000)
```

The correct formula should apply each royalty to the **full** amount:

```
royaltyAmount = (amount * r1/10000) + (amount * r2/10000) + ...
              = amount * (r1 + r2 + ... + rN) / 10000
```

The result is that the displayed total is understated by a factor of N.

This value is surfaced as `amountWithRoyalties` in the WalletConnect confirmation dialog, which is the primary signal a user relies on when deciding whether to approve a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` command. [2](#0-1) 

The `withRoyaltyTotals` function passes this understated value into the `DisplayWalletDeltaItem` that is rendered in the approval dialog.

### Impact Explanation

A user accepting a WalletConnect offer for multiple NFTs (each with royalties) will see a `amountWithRoyalties` total that is N times lower than the actual amount the transaction will deduct from their wallet. The user approves based on the incorrect lower figure; the on-chain transaction enforces the correct (higher) royalty amounts. This constitutes a WalletConnect state corruption that causes a user to approve the wrong amount — a **High** impact per the allowed scope.

### Likelihood Explanation

Any WalletConnect-connected dApp can present a `take_offer` command with 2+ NFTs each carrying royalties. No special privileges are required. The bug is triggered automatically by the multi-NFT path in `formatAmountWithRoyalties`. The test at line 251–335 of `parseCommandDisplay.test.ts` even exercises this exact scenario and asserts the (incorrect) understated value as the expected output, confirming the bug is present and undetected. [3](#0-2) 

### Recommendation

Remove the erroneous division by `royaltyPercentages.length`. Each NFT's royalty should be applied to the full fungible amount:

```typescript
// Correct: apply each royalty to the full amount
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
```

The `splitAmount` variable and its division should be removed entirely.

### Proof of Concept

Scenario: WalletConnect dApp sends `chia_wallet.take_offer` for an offer where the user spends **100,000,000 mojos** (0.1 XCH) to receive 2 NFTs — NFT-A with 5% royalty (500 basis points) and NFT-B with 0.1% royalty (10 basis points).

**Buggy calculation (current code):**
- `splitAmount = 100_000_000 / 2 = 50_000_000`
- royalty for NFT-A: `50_000_000 * 500 / 10_000 = 2_500_000`
- royalty for NFT-B: `50_000_000 * 10 / 10_000 = 50_000`
- `totalAmount = 100_000_000 + 2_550_000 = 102_550_000` → displayed as `0.00010255 XCH`

**Correct calculation:**
- royalty for NFT-A: `100_000_000 * 500 / 10_000 = 5_000_000`
- royalty for NFT-B: `100_000_000 * 10 / 10_000 = 100_000`
- `totalAmount = 100_000_000 + 5_100_000 = 105_100_000` → should display `0.0001051 XCH`

The user sees `0.00010255 XCH` in the WalletConnect approval dialog and approves, but the actual transaction deducts `0.0001051 XCH` — approximately 2× the displayed royalty cost. The existing test at line 320 asserts `amountWithRoyalties: '0.00010255'`, confirming the buggy value is the current output. [4](#0-3)

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
