### Title
BigInt Truncation in Multi-NFT Royalty Display Understates Spending Total in WalletConnect Approval — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly splits the fungible amount equally across all NFTs before computing each royalty contribution. Combined with two layers of BigInt integer truncation, this causes the `amountWithRoyalties` field shown in the WalletConnect signing-approval dialog to be materially understated for any offer involving more than one NFT with royalties. A user presented with such an offer via WalletConnect sees a lower total cost than what the blockchain will actually deduct, and may approve a transaction they would otherwise reject.

### Finding Description

`formatAmountWithRoyalties` is called from `withRoyaltyTotals` → `walletDeltaToDisplay` → `parseCommandDisplay`, which is the function that produces the structured display object rendered in the Electron WalletConnect confirmation dialog before the user approves a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` command. [1](#0-0) 

The flawed calculation:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ① truncating BigInt division
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) =>
    total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,  // ② truncating BigInt division
  0n,
);
```

**What the code computes** (N = number of NFTs):

```
royaltyAmount ≈ (amount / N) * Σ(royaltyPercentage_i) / 10000
```

**What the correct formula is:**

```
royaltyAmount = amount * Σ(royaltyPercentage_i) / 10000
```

The code divides `amount` by N before summing royalties, producing a result that is approximately `1/N` of the correct value. For a two-NFT offer the displayed royalty is roughly half the actual royalty; for three NFTs, one-third; and so on.

**Concrete example** (matching the existing test fixture):

| Parameter | Value |
|---|---|
| `amount` | 100,000,000 mojos (0.0001 XCH) |
| NFT 1 royalty | 500 (5 %) |
| NFT 2 royalty | 10 (0.1 %) |
| **Displayed** `amountWithRoyalties` | 0.00010255 XCH |
| **Correct** `amountWithRoyalties` | 0.0001051 XCH | [2](#0-1) 

The test itself encodes the wrong expected value, confirming the bug is present and undetected.

### Impact Explanation

`amountWithRoyalties` is the only field in the WalletConnect approval dialog that tells the user their true all-in cost (base price + creator royalties). When it is understated, the user approves a `take_offer` transaction believing the total XCH or CAT deduction will be X, while the blockchain enforces a deduction of X + delta (the missing royalty portion). For high-royalty or many-NFT offers the delta can be a significant fraction of the total cost. This directly causes a user to approve the wrong spending amount via WalletConnect.

### Likelihood Explanation

Any WalletConnect-connected dApp or malicious peer can present a `take_offer` payload containing two or more NFTs with non-zero royalties. No special privileges are required. The victim only needs to have a WalletConnect session open and interact with the approval dialog. The discrepancy grows with the number of NFTs and the royalty percentages, making it straightforward to craft an offer where the displayed total is materially lower than the actual deduction.

### Recommendation

Replace the split-then-multiply approach with a per-NFT calculation on the full `amount`:

```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  // Compute each NFT's royalty on the full amount, not a split amount.
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) =>
      total + (amount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;

  if (line.kind === 'xch') {
    return mojoToChiaLocaleString(totalAmount);
  }
  return mojoToCATLocaleString(totalAmount);
}
```

Update the corresponding test expectations to reflect the corrected values.

### Proof of Concept

Using the existing test fixture in `parseCommandDisplay.test.ts`:

- Offer: 0.0001 XCH for two NFTs (royalties 5 % and 0.1 %)
- Current displayed `amountWithRoyalties`: **0.00010255 XCH**
- Correct `amountWithRoyalties`: **0.0001051 XCH**

A WalletConnect dApp presents this offer. The user sees the approval dialog showing a total spend of 0.00010255 XCH. They approve. The blockchain deducts 0.0001051 XCH — roughly 2.4 % more than the user was shown. Scaling to larger amounts or higher royalty percentages (e.g., 10 % royalty on a 10 XCH offer with 3 NFTs) produces a displayed understatement of thousands of mojos. [3](#0-2)

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
