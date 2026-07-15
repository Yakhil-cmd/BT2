### Title
WalletConnect Offer Signing Dialog Systematically Underestimates Royalty Totals for Multi-NFT Offers — (File: `packages/gui/src/electron/commands/parseCommandDisplay.ts`)

---

### Summary

`formatAmountWithRoyalties` in `parseCommandDisplay.ts` divides the fungible payment amount by the number of NFTs before computing each royalty, causing the "Total Amount with Royalties" shown in the WalletConnect signing confirmation dialog to be systematically lower than the amount that will actually be deducted from the user's wallet when accepting a multi-NFT offer.

---

### Finding Description

The function `formatAmountWithRoyalties` is called during `chia_wallet.take_offer` WalletConnect request processing to compute the displayed total cost including creator royalties: [1](#0-0) 

```typescript
const splitAmount = amount / BigInt(royaltyPercentages.length);   // ← divides by N first
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

For N NFTs, the code computes each royalty against `amount / N` (integer division, truncating) rather than against the full `amount`. The Chia protocol applies each NFT's royalty to the full fungible trade amount, so the correct formula is:

```
royaltyAmount = Σ (amount × royaltyPercentage_i / 10_000)
```

The buggy formula produces:

```
royaltyAmount = Σ ((amount / N) × royaltyPercentage_i / 10_000)
             = (amount / N) × Σ royaltyPercentage_i / 10_000
```

This is N times smaller than the correct value. The existing test at line 251 encodes the wrong result as the expected value, confirming the bug is present and untested against the correct on-chain behavior: [2](#0-1) 

The computed `amountWithRoyalties` string is then rendered directly in the WalletConnect signing confirmation dialog: [3](#0-2) 

---

### Impact Explanation

A user accepting a multi-NFT offer via WalletConnect sees a "Total Amount with Royalties" that is materially lower than what the blockchain will actually deduct. The user approves based on the understated figure; the actual on-chain spend is higher, with the excess going to the NFT creator (the attacker). This is a direct, concrete asset loss caused by a wrong amount displayed in the WalletConnect approval flow.

**Concrete example** (from the test scenario at lines 251–335):
- Payment: 100,000,000 mojos (0.0001 XCH)
- NFT1 royalty: 500 bp (5%), NFT2 royalty: 10 bp (0.1%)
- **Displayed total**: 0.00010255 XCH (what the user approves)
- **Correct on-chain total**: 0.0001051 XCH (what is actually deducted)
- **Discrepancy**: ~0.0000026 XCH per 0.0001 XCH trade; scales linearly with trade size and royalty rates

For a 10 XCH trade with two NFTs each carrying 10% royalty, the user would see 11 XCH but pay 12 XCH.

---

### Likelihood Explanation

The attacker path requires only:
1. Minting two or more NFTs with royalty percentages set at mint time (normal, unprivileged action).
2. Creating an offer that bundles those NFTs against a fungible payment.
3. Delivering the offer string to a victim via WalletConnect (`chia_wallet.take_offer`).

No key compromise, phishing, or host access is required. The royalty percentages used in the display come from `nftGetInfo` (on-chain data fetched by the local node), so the attacker does not need to forge any data — the underestimation is a pure arithmetic defect triggered by any multi-NFT offer.

---

### Recommendation

Remove the `/ BigInt(royaltyPercentages.length)` split. Apply each royalty percentage to the full `amount`:

```typescript
// packages/gui/src/electron/commands/parseCommandDisplay.ts
const royaltyAmount = royaltyPercentages.reduce(
  (total, royaltyPercentage) => total + (amount * BigInt(royaltyPercentage)) / 10_000n,
  0n,
);
```

Update the corresponding test expectation at line 321 (`'0.00010255'` → `'0.0001051'`) to reflect the correct on-chain total.

---

### Proof of Concept

**Setup**: Attacker mints NFT-A (5% royalty) and NFT-B (0.1% royalty). Attacker creates an offer: give NFT-A + NFT-B, receive 100,000,000 mojos.

**WalletConnect request** sent to victim:
```json
{ "method": "chia_wallet.take_offer", "params": { "offer": "<encoded offer string>" } }
```

**Victim's signing dialog shows**:
> Spending: 0.0001 XCH
> Total Amount with Royalties: **0.00010255 XCH**

**Actual blockchain deduction**:
- Base: 100,000,000 mojos
- NFT-A royalty (5% of full amount): 5,000,000 mojos
- NFT-B royalty (0.1% of full amount): 100,000 mojos
- **Total: 105,100,000 mojos = 0.0001051 XCH**

The victim approves 0.00010255 XCH but 0.0001051 XCH is deducted — a 2.5% overcharge relative to the displayed figure, scaling with trade size and royalty rates.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L363-368)
```typescript
  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;
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

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```
