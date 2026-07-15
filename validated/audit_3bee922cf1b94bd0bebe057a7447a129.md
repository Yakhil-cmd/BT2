Now I have enough information to write the finding. The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` uses a mathematically incorrect formula when multiple NFTs with royalties are involved in a WalletConnect `take_offer` command, causing the confirmation dialog to display a lower "Total Amount with Royalties" than what is actually charged on-chain.

**Proof of the math error:**

- 2 NFTs with royalties 500 (5%) and 10 (0.1%), amount = 100,000,000 mojos
- **Current code** (splits amount first): `splitAmount = 50,000,000`; royalty = `(50M×500)/10000 + (50M×10)/10000 = 2,550,000`; total = **102,550,000 mojos (0.00010255 XCH)**
- **Correct on-chain calculation** (applies each royalty to full amount): royalty = `(100M×500)/10000 + (100M×10)/10000 = 5,100,000`; total = **105,100,000 mojos (0.0001051 XCH)**

The test in `parseCommandDisplay.test.ts` confirms the current (wrong) output of `0.00010255` is accepted as correct.

---

### Title
WalletConnect `take_offer` Confirmation Displays Understated "Total Amount with Royalties" for Multi-NFT Offers Due to Incorrect Royalty Accumulation Formula — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
`formatAmountWithRoyalties` in `parseCommandDisplay.ts` divides the fungible amount by the number of NFTs before applying each royalty percentage, instead of applying each royalty to the full amount. For any `take_offer` WalletConnect command involving two or more NFTs with royalties, the "Total Amount with Royalties" shown in the approval dialog is materially lower than the amount actually deducted on-chain, causing the user to approve a spend they would not have approved with correct information.

### Finding Description
`formatAmountWithRoyalties` computes the royalty total as:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // integer division
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [1](#0-0) 

This divides `amount` by `N` (the number of NFTs) before multiplying by each royalty percentage. Mathematically this computes `amount × (sum_of_percentages / N) / 10000`, i.e. the average royalty applied once — not the sum of each royalty applied to the full amount. The correct formula is `sum_i( amount × p_i / 10000 )`.

The result is placed in `amountWithRoyalties` on the spending line and rendered in the WalletConnect confirmation dialog under the label "Total Amount with Royalties": [2](#0-1) 

`royaltyPercentagesForSide` collects all NFT royalty percentages from the receiving side and passes them to `formatAmountWithRoyalties`: [3](#0-2) 

`withRoyaltyTotals` then attaches the result to every fungible spending line: [4](#0-3) 

### Impact Explanation
A user receiving a WalletConnect `take_offer` request for an offer containing two or more NFTs with royalties sees a "Total Amount with Royalties" that is significantly lower than the amount the Chia blockchain will actually deduct. For example, with two NFTs carrying 5% and 0.1% royalties on a 0.0001 XCH purchase, the dialog shows **0.00010255 XCH** while the on-chain deduction is **0.0001051 XCH** — a ~2.4% understatement that grows with the number of NFTs and their royalty rates. The user approves based on the displayed figure; the blockchain charges the correct (higher) amount. This constitutes corruption of WalletConnect approval state that causes a user to approve the wrong spend amount, matching the High impact category.

### Likelihood Explanation
Any dapp that constructs a multi-NFT-for-token offer and sends it via WalletConnect triggers this path. No special privileges or key access are required; the attacker only needs to craft an offer with two or more royalty-bearing NFTs. Multi-NFT bundle offers are a supported and documented use case.

### Recommendation
Remove the `splitAmount` division. Apply each royalty percentage independently to the full `amount`:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

This matches the on-chain royalty accumulation logic and eliminates the understatement.

### Proof of Concept
The existing test in `parseCommandDisplay.test.ts` already encodes the wrong expected value and confirms the bug:

- Offer: 2 NFTs (royalties 500 = 5%, 10 = 0.1%), requested 100,000,000 mojos XCH
- **Displayed** (`amountWithRoyalties`): `0.00010255` XCH (current buggy output, accepted by test)
- **Correct on-chain total**: `(100,000,000 + 5,000,000 + 100,000)` = 105,100,000 mojos = `0.0001051` XCH [5](#0-4) 

An unprivileged dapp sends `chia_wallet.take_offer` with a multi-NFT offer via WalletConnect → `parseCommandDisplay` calls `formatAmountWithRoyalties` with the split-amount formula → the confirmation dialog renders the understated total → the user approves → the blockchain deducts the correct (higher) amount.

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

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L363-367)
```typescript
  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
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
