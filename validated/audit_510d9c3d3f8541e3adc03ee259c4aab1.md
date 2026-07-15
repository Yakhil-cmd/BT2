### Title
Incorrect `nftSellerNetAmount` Calculation Causes NFT Sellers to See Inflated "You Will Receive" / "Net Proceeds" and Disables the Negative-Proceeds Guard - (File: `packages/gui/src/components/offers/utils.ts`)

---

### Summary

`calculateNFTRoyalties` in `packages/gui/src/components/offers/utils.ts` hard-codes `nftSellerNetAmount = amount` (the full asking price) instead of `amount - royaltyAmount` (the actual net after creator royalties). The correct formula is present but commented out. This propagates into two user-facing flows: the NFT offer creation screen ("You will receive") and the offer viewer ("Net Proceeds"), causing sellers to see an inflated figure. It also permanently disables the guard that is supposed to block offers where the seller's net proceeds would be negative.

---

### Finding Description

In `calculateNFTRoyalties`:

```typescript
// packages/gui/src/components/offers/utils.ts  lines 312-317
const royaltyAmount: number = royaltyPercentage ? (royaltyPercentage / 100) * amount : 0;
const royaltyAmountString: string = formatAmount(royaltyAmount);
const nftSellerNetAmount: number = amount;          // BUG: should be amount - royaltyAmount
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
```

The correct subtraction is commented out. `nftSellerNetAmount` is therefore always equal to `amount`, regardless of the royalty percentage. [1](#0-0) 

This value flows into two distinct UI surfaces:

**1. NFT Offer Editor — "You will receive" label (offer creation)**

When a seller is creating an NFT-for-token offer, the editor renders:

```tsx
// NFTOfferEditor.tsx  lines 358-366
{tab === NFTOfferExchangeType.NFTForToken ? (
  <Trans>You will receive</Trans>
) : (
  <Trans>They will receive</Trans>
)}
<FormatLargeNumber value={new BigNumber(nftSellerNetAmount ?? 0)} />
``` [2](#0-1) 

The seller sees the full asking price as their expected receipt, not the price minus creator royalties.

**2. NFT Offer Viewer — "Net Proceeds" label (offer acceptance)**

When a buyer views an imported offer and the exchange type is `TokenForNFT`, the viewer shows:

```tsx
// NFTOfferViewer.tsx  lines 583-597
<Typography variant="h6" color="textSecondary">
  <Trans>Net Proceeds</Trans>
</Typography>
<FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} />
``` [3](#0-2) 

The `overrideNFTSellerAmount` passed to `NFTOfferSummaryRow` is also derived from the same broken value:

```typescript
// NFTOfferViewer.tsx  lines 397-402
const overrideNFTSellerAmount =
  exchangeType === NFTOfferExchangeType.TokenForNFT
    ? assetType === OfferAsset.CHIA
      ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
    : undefined;
``` [4](#0-3) 

**3. Negative-proceeds guard is permanently disabled**

The editor uses `nftSellerNetAmount` to decide whether to block offer creation:

```typescript
// NFTOfferEditor.tsx  line 271
const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
``` [5](#0-4) 

Because `nftSellerNetAmount` is always equal to `amount` (a non-negative user input), this condition is permanently `false`. The error message "Unable to create an offer where the net amount is negative" and the associated block on offer submission can never trigger, even when the royalty percentage exceeds 100% of the asking price. [6](#0-5) 

---

### Impact Explanation

An NFT seller creating an offer for, say, 1 XCH with a 10% creator royalty sees "You will receive: 1 XCH" but the protocol will actually deliver 0.9 XCH to them (the creator receives 0.1 XCH). The seller is shown a materially wrong amount at the moment they decide to publish the offer. This constitutes displaying the wrong amount at the offer-approval decision point, matching the allowed High impact: *"state that causes a user to approve... the wrong... amount... or status."*

The secondary consequence — the permanently-disabled negative-proceeds guard — means a seller with an NFT carrying a very high royalty percentage (e.g., 150%) can publish an offer where they would net nothing or less than nothing, with no warning from the GUI.

---

### Likelihood Explanation

Any NFT with a non-zero `royaltyPercentage` triggers the bug. The royalty percentage is displayed separately (the "Creator Fee (X%)" line is correct), but the pre-computed "You will receive" / "Net Proceeds" summary figure — which is the primary decision-support number shown to the seller — is always wrong by exactly the royalty amount. This affects every NFT offer creation and viewing session involving royalty-bearing NFTs.

---

### Recommendation

Restore the commented-out formula in `calculateNFTRoyalties`:

```typescript
// packages/gui/src/components/offers/utils.ts
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
``` [7](#0-6) 

This will simultaneously fix the "You will receive" / "Net Proceeds" display and re-enable the `showNegativeAmountWarning` guard in `NFTOfferEditor`.

---

### Proof of Concept

1. Open the Chia GUI and navigate to **Offers → Create an Offer → Sell an NFT**.
2. Select an NFT that has a non-zero `royaltyPercentage` (e.g., 10%).
3. Enter an asking price of **1 XCH**.
4. Observe: the "Creator Fee (10%)" line correctly shows **0.1 XCH**, but the "You will receive" line shows **1 XCH** instead of the correct **0.9 XCH**.
5. Publish the offer. The on-chain settlement will deliver 0.9 XCH to the seller, contradicting what the GUI displayed at approval time.

For the guard bypass: set royaltyPercentage to a value that would make `amount - royaltyAmount < 0` (e.g., royalty > 100%). The "Unable to create an offer where the net amount is negative" error never appears and the offer can be submitted.

### Citations

**File:** packages/gui/src/components/offers/utils.ts (L312-317)
```typescript
  const royaltyAmount: number = royaltyPercentage ? (royaltyPercentage / 100) * amount : 0;
  const royaltyAmountString: string = formatAmount(royaltyAmount);
  const nftSellerNetAmount: number = amount;
  // : parseFloat(
  //     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
  //   );
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L271-271)
```typescript
  const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L358-366)
```typescript
                    {tab === NFTOfferExchangeType.NFTForToken ? (
                      <Trans>You will receive</Trans>
                    ) : (
                      <Trans>They will receive</Trans>
                    )}
                  </Typography>
                  <Typography variant="subtitle1" color={showNegativeAmountWarning ? StateColor.ERROR : 'inherit'}>
                    <FormatLargeNumber value={new BigNumber(nftSellerNetAmount ?? 0)} />{' '}
                    {tokenWalletInfo.symbol ?? tokenWalletInfo.name ?? ''}
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L368-372)
```typescript
                  {showNegativeAmountWarning && (
                    <Typography variant="body2" color={StateColor.ERROR}>
                      <Trans>Unable to create an offer where the net amount is negative</Trans>
                    </Typography>
                  )}
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L397-402)
```typescript
  const overrideNFTSellerAmount =
    exchangeType === NFTOfferExchangeType.TokenForNFT
      ? assetType === OfferAsset.CHIA
        ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
        : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : undefined;
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L583-597)
```typescript
                        <Typography variant="h6" color="textSecondary">
                          <Trans>Net Proceeds</Trans>
                        </Typography>
                        <Flex justifyContent="center">
                          <TooltipIcon>
                            <Trans>
                              The net proceeds include the asking price, minus any associated creator fees (if the NFT
                              has royalty payments enabled).
                            </Trans>
                          </TooltipIcon>
                        </Flex>
                      </Flex>
                      <Typography variant="h5" fontWeight="bold">
                        <FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} /> {displayName}
                      </Typography>
```
