### Title
Incorrect Division-Before-Multiplication in Multi-NFT Royalty Calculation Understates "Total Amount with Royalties" in WalletConnect Signing Confirmation — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the offer amount by the number of NFTs before computing each NFT's royalty, rather than applying each royalty to the full amount. This causes the "Total Amount with Royalties" displayed in the WalletConnect signing confirmation dialog to be materially understated whenever an offer involves multiple NFTs with royalties. A user approves the transaction believing they will spend less than the blockchain will actually deduct.

### Finding Description

In `packages/gui/src/electron/commands/parseCommandDisplay.ts`, the `formatAmountWithRoyalties` function computes the royalty-inclusive total shown to the user in the WalletConnect `Confirm` dialog: [1](#0-0) 

The critical lines are:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← integer division first
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

The code first divides `amount` by the number of NFTs (`splitAmount`), then multiplies each royalty percentage by that reduced `splitAmount`. The correct sequence is to multiply the full `amount` by each royalty percentage and then divide by `10_000n`. The current order of operations produces a result that is `1/N` of the correct royalty for each NFT (where N is the number of NFTs in the offer), causing the displayed total to be significantly understated.

**Concrete example** (matching the existing test case at line 251–334 of `parseCommandDisplay.test.ts`):

- `amount` = 100,000,000 mojos (0.0001 XCH)
- 2 NFTs: `royalty_percentage` = 500 (5%) and 10 (0.1%)

| | Current (buggy) | Correct |
|---|---|---|
| splitAmount | 50,000,000 | — |
| royalty NFT1 | (50,000,000 × 500) / 10,000 = **2,500,000** | (100,000,000 × 500) / 10,000 = **5,000,000** |
| royalty NFT2 | (50,000,000 × 10) / 10,000 = **50,000** | (100,000,000 × 10) / 10,000 = **100,000** |
| Total shown | **0.00010255 XCH** | **0.0001051 XCH** |

The user is shown 0.00010255 XCH but the blockchain charges 0.0001051 XCH — a ~2.4% understatement in this example. The discrepancy scales with both the number of NFTs and the royalty percentages.

Additionally, the integer division `amount / BigInt(royaltyPercentages.length)` truncates, introducing a further rounding loss that compounds the understatement.

### Impact Explanation

The `amountWithRoyalties` value is rendered directly in the WalletConnect signing confirmation dialog under the "You Spend" section as "Total Amount with Royalties": [2](#0-1) 

A user presented with a WalletConnect `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request for an offer involving multiple NFTs with royalties sees a lower total cost than what the blockchain will actually deduct. The user approves the transaction based on the understated figure. The actual on-chain royalty amounts are computed correctly by the wallet backend and are higher than displayed, resulting in a larger-than-expected balance reduction.

This matches the **High** impact category: WalletConnect state causes a user to display the wrong amount, leading them to approve a transaction for the wrong (understated) cost.

### Likelihood Explanation

Any WalletConnect-connected dApp can trigger this by sending a `take_offer` or `create_offer_for_ids` request for an offer that bundles two or more NFTs with royalties. No special privileges are required. The dApp does not need to be malicious — the bug fires for any legitimate multi-NFT offer. The discrepancy grows with royalty percentage and NFT count, making it more impactful for high-royalty collections.

### Recommendation

Replace the `splitAmount` pre-division with per-NFT full-amount multiplication:

```typescript
// Current (incorrect):
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);

// Correct:
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Each NFT's royalty must be calculated on the full offer amount, not on a fraction of it.

### Proof of Concept

The existing test at `packages/gui/src/electron/commands/parseCommandDisplay.test.ts` lines 251–334 demonstrates the bug: it asserts `amountWithRoyalties: '0.00010255'` for a 2-NFT offer (royalties 500 and 10) on 100,000,000 mojos. The mathematically correct value is `'0.0001051'`. The test was written to match the buggy behavior, confirming the understatement is present and observable. [3](#0-2) 

A WalletConnect dApp sending:
```json
{
  "method": "chia_wallet.take_offer",
  "params": { "offer": "<offer_with_2_NFTs_each_having_royalties>" }
}
```
will cause the confirmation dialog to display a "Total Amount with Royalties" that is approximately `(1/N)` of the correct royalty sum, where N is the number of NFTs, causing the user to approve a transaction that costs more than shown.

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.test.ts (L251-334)
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
```
