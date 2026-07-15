### Title
WalletConnect `take_offer` Confirmation Dialog Understates True XCH Cost When Multiple Royalty-Bearing NFTs Are Received - (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
The `formatAmountWithRoyalties` function in `parseCommandDisplay.ts` incorrectly calculates the total XCH cost shown in the WalletConnect confirmation dialog when an offer involves multiple NFTs with royalties. It divides the base amount by the number of NFTs before applying each royalty percentage, producing a displayed total that is systematically lower than the actual on-chain cost. A malicious dApp can exploit this to get a user to approve a `chia_takeOffer` WalletConnect command while believing they are spending significantly less XCH than will actually be deducted.

### Finding Description

The `formatAmountWithRoyalties` function is called during the WalletConnect `chia_wallet.take_offer` confirmation flow to compute the `amountWithRoyalties` field shown in the "You Spend" section of the confirmation dialog. [1](#0-0) 

The function receives the full array of royalty percentages from all NFTs on the receiving side and computes:

```
splitAmount = amount / N          // divides base amount by NFT count
royaltyAmount = Σ (splitAmount × rᵢ / 10_000)
totalAmount = amount + royaltyAmount
```

The correct formula — matching what the Chia wallet daemon actually charges on-chain — is:

```
royaltyAmount = Σ (amount × rᵢ / 10_000)   // full amount per NFT
totalAmount = amount + royaltyAmount
```

The displayed total is therefore `amount × (1 + Σrᵢ / (N × 10_000))` while the actual cost is `amount × (1 + Σrᵢ / 10_000)`. The underestimate grows with both the number of NFTs and the royalty percentages.

**Concrete example** — 2 NFTs, each with 50 % royalty (5000 basis points), base amount 1 XCH:
- Displayed: `1 × (1 + 10000 / (2 × 10000))` = **1.5 XCH**
- Actual on-chain: `1 × (1 + 10000 / 10000)` = **2 XCH**

The user approves believing they spend 1.5 XCH; 2 XCH is deducted.

This function is invoked exclusively inside the WalletConnect `DISPATCH_AS_PAIR` IPC handler, which calls `parseCommandDisplay` to populate the confirmation dialog before the user clicks "Accept": [2](#0-1) 

The `chia_wallet.take_offer` command is exposed to dApps as `chia_takeOffer` and always requires user confirmation through this dialog: [3](#0-2) 

The regular (non-WalletConnect) offer acceptance path uses `useCalculateRoyaltiesForNFTsQuery`, which delegates royalty math to the wallet daemon and is not affected.

### Impact Explanation

A user who approves a WalletConnect `chia_takeOffer` request based on the displayed `amountWithRoyalties` figure will have more XCH deducted than shown. The gap scales with the number of NFTs and their royalty rates. With two NFTs at 50 % royalty the user pays 33 % more than displayed; with three NFTs at 50 % royalty the user pays 50 % more. This is a direct, irreversible XCH loss caused by a spoofed spending amount in the approval dialog.

### Likelihood Explanation

The attacker must already hold a WalletConnect session with the victim (the user approved the dApp pairing). Once paired, the dApp can send any number of `chia_takeOffer` requests. The attacker constructs a valid Chia offer that offers multiple NFTs (which the attacker controls or has sourced) with high royalty percentages and requests XCH. The victim sees a lower total than reality and approves. No cryptographic break, key leak, or social engineering beyond the initial dApp pairing is required.

### Recommendation

Replace the split-then-sum logic with the correct per-NFT full-amount calculation:

```typescript
// Correct: apply each royalty to the full amount
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Remove the `splitAmount` variable entirely.

### Proof of Concept

The existing test at line 251–335 of `parseCommandDisplay.test.ts` already demonstrates the bug implicitly: with two NFTs at 500 bp and 10 bp royalties and a base of 100,000,000 mojos, the test asserts `amountWithRoyalties: '0.00010255'`. [4](#0-3) 

Correct calculation:
- NFT1 royalty: 100,000,000 × 500 / 10,000 = 5,000,000 mojos
- NFT2 royalty: 100,000,000 × 10 / 10,000 = 100,000 mojos
- Correct total: 105,100,000 mojos = **0.0001051 XCH**

Buggy display: 102,550,000 mojos = **0.00010255 XCH** (royalties halved because `splitAmount = amount / 2`).

A malicious dApp sends `chia_takeOffer` with an offer containing two NFTs each carrying 5000 bp (50 %) royalties and requests 1 XCH. The dialog shows **1.5 XCH**; the wallet deducts **2 XCH** upon approval.

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

**File:** packages/gui/src/electron/main.tsx (L329-344)
```typescript
          const display = await parseCommandDisplay(commandId, parsedParams);

          const confirmResult = await openReactDialog<ConfirmDialogResult, ConfirmProps>(
            mainWindow,
            Confirm,
            {
              networkPrefix,
              command: commandId,
              data: parsedParams,
              title,
              message,
              confirmLabel,
              destructive,
              rows,
              pair,
              display,
```

**File:** packages/gui/src/electron/commands/Commands.ts (L349-370)
```typescript
  'chia_wallet.take_offer': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Take Offer' }),
    message: () => i18n._(/* i18n */ { id: 'Please carefully review and confirm this offer acceptance.' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Accept' }),
    params: [
      { name: 'fee', label: () => i18n._(/* i18n */ { id: 'Fee' }), type: 'bigint', humanize: 'mojo-to-xch' },
      { name: 'offer', label: () => i18n._(/* i18n */ { id: 'Offer' }), type: 'string' },
      // TODO verify rest if needed for DAPP, if not use for dapp separate params
      {
        name: 'extra_conditions',
        label: () => i18n._(/* i18n */ { id: 'Extra Conditions' }),
        type: 'json',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_takeOffer',
        title: () => i18n._(/* i18n */ { id: 'Take Offer' }),
      },
    ],
  },
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
