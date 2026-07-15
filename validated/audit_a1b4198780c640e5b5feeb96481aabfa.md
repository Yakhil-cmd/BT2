### Title
WalletConnect Offer Confirmation Understates Royalty Cost for Multi-NFT Offers — (`File: packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
`formatAmountWithRoyalties` in `parseCommandDisplay.ts` incorrectly splits the fungible amount equally across all NFTs before applying each NFT's royalty percentage. For a single NFT the result is correct, but for N NFTs the displayed "Total Amount with Royalties" is understated by a factor of N. A WalletConnect-connected dApp can exploit this to make a victim approve a `take_offer` transaction while seeing a materially lower cost than what the wallet will actually deduct.

### Finding Description

The function `formatAmountWithRoyalties` computes the royalty-inclusive total shown in the WalletConnect `Confirm` dialog:

```typescript
// parseCommandDisplay.ts lines 363-367
const splitAmount = amount / BigInt(royaltyPercentages.length);
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [1](#0-0) 

`splitAmount` divides the full fungible amount by the number of NFTs before multiplying by each royalty percentage. The correct formula is to apply each royalty percentage to the **full** amount:

| Scenario | Displayed total | Correct total |
|---|---|---|
| 1 NFT, 10 % royalty, 1 XCH | 1.1 XCH ✓ | 1.1 XCH |
| 2 NFTs, 10 % each, 1 XCH | 1.1 XCH ✗ | 1.2 XCH |
| 3 NFTs, 10 % each, 1 XCH | 1.1 XCH ✗ | 1.3 XCH |

The `royaltyPercentages` array fed into this function is built by `royaltyPercentagesForSide`, which collects the `royaltyPercentage` field from every NFT `DisplayWalletDeltaItem` on the opposite side of the trade. [2](#0-1) 

For `take_offer`, those percentages are populated from the daemon-returned offer summary `infos` field and then overridden by a live `nftGetInfo` RPC call, so they reflect real on-chain royalty data — the attacker does not need to forge them. [3](#0-2) 

The resulting `amountWithRoyalties` string is surfaced in the `Confirm` dialog as **"Total Amount with Royalties"**, the primary cost figure shown to the user before they click Approve. [4](#0-3) 

### Impact Explanation

A WalletConnect dApp sends a `take_offer` request containing an offer for multiple NFTs that each carry on-chain royalty percentages. The confirmation dialog renders a "Total Amount with Royalties" that is `1/N` of the correct royalty cost. The user approves believing they are spending, e.g., 1.1 XCH; the wallet daemon deducts the correct 1.3 XCH. The royalty surplus flows to the NFT creator (the attacker). This is a **High** impact: WalletConnect state spoofing that causes the user to approve the wrong spend amount, matching the allowed impact class "Corruption, spoofing, or unsafe trust of … WalletConnect state that causes a user to approve … the wrong … amount."

### Likelihood Explanation

The attacker must already hold an approved WalletConnect session (normal dApp usage, not a privilege escalation). They then mint NFTs with royalty percentages on-chain and craft a multi-NFT offer. No cryptographic break, key leak, or social engineering beyond the standard WalletConnect pairing flow is required. The bug is triggered deterministically whenever `royaltyPercentages.length > 1`.

### Recommendation

Remove the `splitAmount` division. Apply each royalty percentage to the full `amount`:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [5](#0-4) 

### Proof of Concept

The existing test at line 251 of `parseCommandDisplay.test.ts` already demonstrates the incorrect output. With two NFTs having royalty percentages 500 and 10 (basis points) and a spend of 100 000 000 mojos (0.0001 XCH):

- **Current displayed value**: `0.00010255` XCH  
  (`splitAmount = 50 000 000`; royalty = `(50 000 000 × 500)/10 000 + (50 000 000 × 10)/10 000 = 2 550 000`)
- **Correct value**: `0.0001051` XCH  
  (royalty = `(100 000 000 × 500)/10 000 + (100 000 000 × 10)/10 000 = 5 100 000`) [6](#0-5) 

The discrepancy scales linearly with the number of NFTs: three NFTs with 10 % royalties each would display a 10 % total cost increase instead of the correct 30 %, causing the user to approve a transaction that costs three times more in royalties than the confirmation dialog indicated.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L302-328)
```typescript
  if (assetKind === 'nft') {
    const nftId = hexToNftId(key);

    const result: DisplayWalletDeltaItem = {
      kind: 'nft',
      nftId,
      royaltyPercentage,
    };

    try {
      const nftInfo = await nftGetInfo(key);
      if (nftInfo && nftInfo.success && nftInfo.nft_info && nftInfo.nft_info.data_uris) {
        const previewUrl = nftInfo.nft_info.data_uris.find((u) => isValidURL(u));

        if (previewUrl) {
          result.previewUrl = previewUrl;
        }

        if ('royalty_percentage' in nftInfo.nft_info) {
          result.royaltyPercentage = parseRoyaltyPercentage(nftInfo.nft_info.royalty_percentage);
        }
      }
    } catch {
      // NFT type has already been resolved from offer data; metadata is best effort.
    }

    return result;
```

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
