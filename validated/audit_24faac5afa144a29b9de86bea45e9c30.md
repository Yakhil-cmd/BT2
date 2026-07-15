### Title
`formatAmountWithRoyalties()` Divides Amount by NFT Count Before Computing Royalties, Understating "Total Amount with Royalties" in WalletConnect Confirmation Dialog — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

---

### Summary

`formatAmountWithRoyalties()` in `parseCommandDisplay.ts` incorrectly divides the spending amount by the number of NFTs on the opposite side of a trade before computing each NFT's royalty contribution. This causes the "Total Amount with Royalties" label shown in the WalletConnect `chia_wallet.take_offer` / `chia_wallet.create_offer_for_ids` confirmation dialog to be systematically understated — by a factor of `1/N` per NFT — relative to what the blockchain will actually charge. A user who relies on this figure to decide whether to approve a WalletConnect request may consent to paying significantly more than the dialog indicates.

---

### Finding Description

`formatAmountWithRoyalties` is called by `withRoyaltyTotals`, which is called inside `walletDeltaToDisplay` for both `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids` commands. Its job is to compute the string shown as "Total Amount with Royalties" in the WalletConnect confirmation dialog rendered by `Confirm.tsx`.

The buggy arithmetic:

```typescript
// parseCommandDisplay.ts lines 363-367
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by NFT count
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

`royaltyPercentages` is the array of royalty basis-point values for **all** NFTs on the receiving side (collected by `royaltyPercentagesForSide`). Each NFT's royalty in Chia is computed on the **full** fungible amount paid, not on a proportional share. The `splitAmount` division is therefore wrong: it gives each NFT only `amount / N` as its royalty base instead of the full `amount`.

The correct formula is:

```
royaltyAmount = Σ (amount × royaltyPercentage_i) / 10_000
```

The code computes instead:

```
royaltyAmount = Σ ((amount / N) × royaltyPercentage_i) / 10_000
             = (1/N) × Σ (amount × royaltyPercentage_i) / 10_000
```

For N NFTs the displayed royalty is exactly `1/N` of the actual royalty. The discrepancy grows with both the number of NFTs and their royalty percentages.

The incorrect `amountWithRoyalties` string is rendered directly in the confirmation dialog:

```tsx
// Confirm.tsx lines 109-114
{line.amountWithRoyalties && (
  <div className="text-xs text-chia-text-secondary">
    {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
    {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
  </div>
)}
```

This is the **only** place in the WalletConnect approval flow where the user can see the full cost of accepting an NFT offer including royalties. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**High** — The WalletConnect confirmation dialog is the user's sole security checkpoint before signing an offer. The "Total Amount with Royalties" line is explicitly provided so the user can see the true cost including creator fees. When this figure is understated by `1/N` of the actual royalty, the user approves a transaction believing they are paying less than they actually will be charged. The actual on-chain deduction is correct (determined by the blockchain), so the user's wallet is debited the full royalty amount despite the dialog showing a lower figure. This fits the allowed High impact: *"WalletConnect state that causes a user to approve… the wrong… amount."* [3](#0-2) 

---

### Likelihood Explanation

Any dApp that has established a WalletConnect session with the user can send `chia_wallet.take_offer` with an offer blob containing multiple NFTs. If the dApp operator is also the NFT creator (royalty recipient), they directly benefit from the user paying more royalties than the dialog indicates. The attack requires only a valid WalletConnect pairing — no leaked keys, no host compromise, and no cryptographic break. The existing test suite encodes the buggy expected value (`0.00010255` instead of the correct `0.0001051`), confirming the defect is present and not caught by tests. [4](#0-3) 

---

### Recommendation

Remove the `splitAmount` division and compute each NFT's royalty on the full `amount`:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  // Each NFT's royalty is computed on the full amount, not a proportional share.
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

Update the corresponding test expectations to reflect the corrected values. [5](#0-4) 

---

### Proof of Concept

Using the existing test scenario (lines 251–335 of `parseCommandDisplay.test.ts`):

- **Spending**: 100,000,000 mojos (0.0001 XCH)
- **Receiving**: 2 NFTs — royalty 500 bp (5%) and royalty 10 bp (0.1%)

**Buggy calculation (current code):**
```
splitAmount = 100_000_000 / 2 = 50_000_000
royaltyAmount = (50_000_000 × 500) / 10_000 + (50_000_000 × 10) / 10_000
             = 2_500_000 + 50_000 = 2_550_000
totalAmount  = 102_550_000 mojos → displayed as "0.00010255 XCH"
```

**Correct calculation:**
```
royaltyAmount = (100_000_000 × 500) / 10_000 + (100_000_000 × 10) / 10_000
             = 5_000_000 + 100_000 = 5_100_000
totalAmount  = 105_100_000 mojos → should display "0.0001051 XCH"
```

The dialog understates the royalty by **50%** (2,550,000 mojos shown vs. 5,100,000 mojos actually charged). A malicious dApp offering NFTs with higher royalties (e.g., 50% each) across multiple NFTs would produce a proportionally larger discrepancy, causing the user to approve a transaction where the actual deduction is a multiple of what the dialog shows. [6](#0-5) [7](#0-6)

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L195-205)
```typescript
          {i18n._(/* i18n */ { id: 'You Spend' })}
        </div>
        <div className="mt-1.5 flex flex-col gap-1.5">
          {walletDelta.spending.length === 0 ? (
            <span className="text-sm text-chia-text-secondary">{i18n._(/* i18n */ { id: 'Nothing' })}</span>
          ) : (
            walletDelta.spending.map((line, i) => (
              <OfferLineRow key={offerLineKey(line, i)} line={line} networkPrefix={networkPrefix} />
            ))
          )}
        </div>
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
