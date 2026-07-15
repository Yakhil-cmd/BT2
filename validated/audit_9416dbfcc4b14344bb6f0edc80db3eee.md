### Title
Understated "Total Amount with Royalties" in WalletConnect Multi-NFT Offer Approval Causes User to Approve Wrong Spend Amount - (File: packages/gui/src/electron/commands/parseCommandDisplay.ts)

### Summary
`formatAmountWithRoyalties` in `parseCommandDisplay.ts` divides the fungible amount by the number of NFTs before applying each royalty percentage, producing a royalty total that is `1/N` of the correct value when `N > 1` NFTs are involved. The resulting understated `amountWithRoyalties` string is rendered as **"Total Amount with Royalties"** in the WalletConnect confirmation dialog (`Confirm.tsx`), which is the primary figure a user relies on when deciding to approve a `chia_wallet.take_offer` or `chia_wallet.create_offer_for_ids` WalletConnect command.

### Finding Description

`formatAmountWithRoyalties` receives the full fungible `amount` and an array of `royaltyPercentages` (one per NFT on the opposite side of the offer). It first computes:

```js
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← wrong divisor
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [1](#0-0) 

Each royalty should be applied to the **full** `amount` (the taker pays the full price for each NFT's royalty). Instead, the code applies each royalty to `amount / N`, so the total royalty is understated by a factor of `N`.

**Concrete example** (from the existing test):
- Offer: 2 NFTs with royalties 500 (5 %) and 10 (0.1 %), XCH amount = 100,000,000 mojos
- **Buggy display**: `splitAmount` = 50,000,000 → royalty = 2,500,000 + 50,000 = 2,550,000 → total = **102,550,000 mojos (0.00010255 XCH)**
- **Correct value**: royalty = 5,000,000 + 100,000 = 5,100,000 → total = **105,100,000 mojos (0.0001051 XCH)** [2](#0-1) 

The test itself asserts the wrong value (`0.00010255`), confirming the bug is baked in and undetected.

The computed `amountWithRoyalties` string is attached to the spending-side `DisplayWalletDeltaItem` and rendered in the WalletConnect confirmation dialog as **"Total Amount with Royalties"**: [3](#0-2) [4](#0-3) 

### Impact Explanation

When a WalletConnect dApp sends a `take_offer` or `create_offer_for_ids` request involving multiple NFTs with royalties, the user's confirmation dialog shows a "Total Amount with Royalties" that is materially lower than what will actually be deducted from their wallet. The user approves based on the understated figure; the backend then executes the transaction at the correct (higher) royalty-inclusive cost. This constitutes WalletConnect state spoofing that causes a user to approve the wrong spend amount — a direct match to the High-impact category.

The understatement scales with both the number of NFTs and the royalty percentages. With 5 NFTs each carrying a 10 % royalty, the displayed royalty total would be 1/5 of the correct value, hiding 80 % of the actual royalty cost from the user.

### Likelihood Explanation

Medium. The attacker must control a WalletConnect-paired dApp and craft an offer containing ≥ 2 NFTs with non-zero royalties. Multi-NFT bundle offers are a supported and advertised use case. No special privileges, leaked keys, or cryptographic breaks are required — only a WalletConnect pairing, which any dApp can request.

### Recommendation

Remove the `splitAmount` division. Each royalty percentage should be applied to the full `amount`:

```js
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test assertion from `'0.00010255'` to `'0.0001051'` to reflect the correct value. [5](#0-4) 

### Proof of Concept

1. A WalletConnect dApp pairs with the Chia GUI wallet.
2. The dApp calls `chia_wallet.take_offer` with an offer string encoding 2 NFTs — NFT-A (royalty 5 %, launcher `0xAAAA…`) and NFT-B (royalty 5 %, launcher `0xBBBB…`) — in exchange for 1 XCH.
3. `parseCommandDisplay` calls `formatAmountWithRoyalties(line, 1_000_000_000_000n, [500, 500])`.
4. `splitAmount` = 500,000,000,000; royaltyAmount = (500B × 500 / 10000) + (500B × 500 / 10000) = 25,000,000,000 + 25,000,000,000 = 50,000,000,000.
5. Dialog shows **"Total Amount with Royalties: 1.05 XCH"**.
6. Correct value: (1T × 500 / 10000) + (1T × 500 / 10000) = 100,000,000,000 → **1.1 XCH**.
7. User approves at the displayed 1.05 XCH; the backend deducts 1.1 XCH (plus the base 1 XCH offer price), spending 0.05 XCH more than the user was shown. [6](#0-5)

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L19-23)
```typescript
export type DisplayWalletDeltaItem =
  | { kind: 'xch'; amount: string; amountWithRoyalties?: string }
  | { kind: 'wallet'; walletId: string; amount: string; walletName?: string; amountWithRoyalties?: string }
  | { kind: 'cat'; amount: string; assetId: string; symbol?: string; amountWithRoyalties?: string }
  | { kind: 'nft'; nftId: string; name?: string; previewUrl?: string; royaltyPercentage?: number };
```
