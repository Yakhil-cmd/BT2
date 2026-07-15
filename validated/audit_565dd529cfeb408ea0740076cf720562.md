### Title
WalletConnect Offer Approval Displays Underestimated Royalty Total for Multi-NFT Offers — (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

---

### Summary

The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly divides the fungible amount by the number of NFTs before computing each NFT's royalty contribution. When a WalletConnect `take_offer` or `create_offer_for_ids` request involves N NFTs with royalties, the `amountWithRoyalties` shown in the approval dialog is approximately 1/N of the correct total. The user approves believing they will spend less than the offer actually requires.

---

### Finding Description

`formatAmountWithRoyalties` is called during WalletConnect command display to compute the "total including royalties" figure shown to the user before they confirm a spend:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides first
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The intent is to sum each NFT's royalty over the full `amount`. The bug is that `splitAmount = amount / N` is used as the base for every royalty term instead of `amount` itself. The correct formula is:

```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

The implemented formula computes:

```
royaltyAmount = Σ ((amount / N) × royaltyPercentage_i / 10_000)
              = (1/N) × Σ (amount × royaltyPercentage_i / 10_000)
```

This is exactly 1/N of the correct value.

The resulting `amountWithRoyalties` string is attached to the spending line and rendered in the WalletConnect confirmation dialog (`WalletDeltaSection` → `OfferLineRow`), which is the primary signal users rely on when deciding whether to approve. [2](#0-1) [3](#0-2) 

---

### Impact Explanation

A user accepting a multi-NFT offer via WalletConnect sees a "Total including royalties" figure that is systematically lower than the amount the offer will actually deduct. With two NFTs the displayed royalty is halved; with ten NFTs it is one-tenth of the real value. The user approves a spend they would not have approved had the correct figure been shown. This constitutes a WalletConnect state display error that causes a user to approve the wrong amount — matching the **High** impact tier ("WalletConnect state that causes a user to approve… the wrong… amount").

Concrete example (from the existing test):

| Scenario | Displayed `amountWithRoyalties` | Correct value |
|---|---|---|
| 1 NFT, royalty 250 bp, 1 XCH | `1.025` XCH | `1.025` XCH ✓ |
| 2 NFTs, royalties 500 + 10 bp, 0.0001 XCH | `0.00010255` XCH | `0.0001051` XCH ✗ | [4](#0-3) 

---

### Likelihood Explanation

No special privileges are required. Any WalletConnect-connected dApp can issue a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` request referencing an offer that bundles two or more NFTs with royalties. The miscalculation fires automatically whenever `royaltyPercentages.length > 1`. [5](#0-4) 

---

### Recommendation

Replace `splitAmount` with `amount` in the royalty accumulator so each NFT's royalty is computed against the full fungible amount:

```typescript
// Before (wrong)
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, rp) => total + (splitAmount * BigInt(rp)) / 10_000n,
  0n,
);

// After (correct)
const royaltyAmount = royaltyPercentages.reduce(
  (total, rp) => total + (amount * BigInt(rp)) / 10_000n,
  0n,
);
``` [6](#0-5) 

---

### Proof of Concept

The existing unit test at line 251–334 of `parseCommandDisplay.test.ts` already demonstrates the bug: with two NFTs carrying royalties of 500 bp and 10 bp against 100 000 000 mojos, the function returns `amountWithRoyalties: '0.00010255'`. The mathematically correct value is `0.0001051` (royalty = 5 000 000 + 100 000 = 5 100 000 mojos; total = 105 100 000 mojos). The displayed figure is exactly half the correct figure because `splitAmount = 100000000n / 2n = 50000000n` is used as the royalty base instead of `100000000n`. [7](#0-6)

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L19-23)
```typescript
export type DisplayWalletDeltaItem =
  | { kind: 'xch'; amount: string; amountWithRoyalties?: string }
  | { kind: 'wallet'; walletId: string; amount: string; walletName?: string; amountWithRoyalties?: string }
  | { kind: 'cat'; amount: string; assetId: string; symbol?: string; amountWithRoyalties?: string }
  | { kind: 'nft'; nftId: string; name?: string; previewUrl?: string; royaltyPercentage?: number };
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L196-205)
```typescript
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
