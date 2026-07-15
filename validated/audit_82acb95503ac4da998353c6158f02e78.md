### Title
Incorrect Multi-NFT Royalty Total in WalletConnect Confirmation Dialog Understates Actual Spend - (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

### Summary
`formatAmountWithRoyalties` in `parseCommandDisplay.ts` incorrectly divides the payment amount by the number of NFTs before computing each NFT's royalty contribution. When a WalletConnect-initiated offer involves multiple NFTs, the `amountWithRoyalties` shown in the signing confirmation dialog is understated by a factor of N (number of NFTs), causing the user to approve a transaction believing they will spend less than they actually will.

### Finding Description

In `formatAmountWithRoyalties`:

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);  // BUG: divides first
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
const totalAmount = amount + royaltyAmount;
``` [1](#0-0) 

The code computes `splitAmount = amount / N` and then applies each NFT's royalty percentage to that split amount. The correct formula is to apply each royalty percentage to the full `amount`:

- **Correct**: `royaltyAmount = Σ (amount × R_i / 10_000)`
- **Buggy**: `royaltyAmount = Σ ((amount / N) × R_i / 10_000)`

The existing test case for two NFTs (5% and 0.1% royalties, 0.0001 XCH payment) confirms the buggy behavior is the actual behavior:

- **Correct total**: 0.0001 + 0.0001×0.05 + 0.0001×0.001 = **0.0001051 XCH**
- **Displayed total**: **0.00010255 XCH** (as asserted in the test) [2](#0-1) 

The test itself validates the incorrect value, confirming this is the live behavior.

### Impact Explanation

The `amountWithRoyalties` field is computed in `parseCommandDisplay` and surfaced in the WalletConnect signing confirmation dialog (`Confirm.tsx`) as the total the user will spend. When a user is presented with a multi-NFT offer via WalletConnect, the dialog shows an understated total cost. The user approves believing they will spend less XCH/CAT than the transaction actually deducts. The actual royalty payments are enforced by the protocol and will exceed what was displayed. [3](#0-2) 

### Likelihood Explanation

An attacker can craft a valid offer containing multiple NFTs (each with royalties) requesting XCH or CAT, then deliver it to a victim via WalletConnect. The victim's confirmation dialog will show a lower-than-actual total. The more NFTs in the offer and the higher the royalty percentages, the greater the discrepancy. This requires no special privileges — any party can create a multi-NFT offer.

### Recommendation

Remove the `splitAmount` division. Each NFT's royalty should be computed against the full `amount`:

```typescript
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
``` [4](#0-3) 

### Proof of Concept

Using the existing test scenario (two NFTs, royalties 500 and 10 basis points, payment 100,000,000 mojos):

- Buggy code: `splitAmount = 50_000_000`; royalties = `(50_000_000×500/10_000) + (50_000_000×10/10_000)` = `2_500_000 + 50_000` = `2_550_000`; displayed total = `102_550_000` mojos = **0.00010255 XCH**
- Correct: royalties = `(100_000_000×500/10_000) + (100_000_000×10/10_000)` = `5_000_000 + 100_000` = `5_100_000`; correct total = `105_100_000` mojos = **0.0001051 XCH**

The user is shown a total ~2% lower than actual for this case; with more NFTs or higher royalties the gap grows proportionally. [5](#0-4)

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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L183-232)
```typescript
function WalletDeltaSection({
  walletDelta,
  networkPrefix,
}: {
  walletDelta: NonNullable<ConfirmDisplay['walletDelta']>;
  networkPrefix?: string;
}) {
  const feeUnit = networkPrefix ? networkPrefix.toUpperCase() : 'XCH';
  return (
    <section className="rounded-xl border border-chia-border bg-chia-card overflow-hidden divide-y divide-chia-border">
      <div className="px-5 py-2.5">
        <div className="text-xs font-semibold uppercase tracking-wider text-chia-text-muted">
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
      </div>
      <div className="px-5 py-2.5">
        <div className="text-xs font-semibold uppercase tracking-wider text-chia-text-muted">
          {i18n._(/* i18n */ { id: 'You Receive' })}
        </div>
        <div className="mt-1.5 flex flex-col gap-1.5">
          {walletDelta.receiving.length === 0 ? (
            <span className="text-sm text-chia-text-secondary">{i18n._(/* i18n */ { id: 'Nothing' })}</span>
          ) : (
            walletDelta.receiving.map((line, i) => (
              <OfferLineRow key={offerLineKey(line, i)} line={line} networkPrefix={networkPrefix} />
            ))
          )}
        </div>
      </div>
      {walletDelta.fee !== undefined && (
        <div className="px-5 py-2.5">
          <div className="text-xs font-semibold uppercase tracking-wider text-chia-text-muted">
            {i18n._(/* i18n */ { id: 'Offer Fees' })}
          </div>
          <div className="mt-0.5 text-sm font-medium text-chia-text">
            {walletDelta.fee} {feeUnit}
          </div>
        </div>
      )}
    </section>
  );
```
