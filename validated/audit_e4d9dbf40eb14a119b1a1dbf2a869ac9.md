### Title
`calculateNFTRoyalties` computes royalty amount but never applies it to `nftSellerNetAmount`, making the net-proceeds display and negative-amount guard useless - (`File: packages/gui/src/components/offers/utils.ts`)

### Summary
`calculateNFTRoyalties` correctly derives `royaltyAmount` from the NFT's royalty percentage, but the result is never subtracted from `nftSellerNetAmount`. The commented-out formula makes clear the deduction was written and then disabled. As a result, the seller's displayed net proceeds always equal the full asking price, and the guard that is supposed to block offers where royalties exceed the asking price can never fire.

### Finding Description
In `calculateNFTRoyalties`, `royaltyAmount` is computed correctly, but `nftSellerNetAmount` is unconditionally set to the raw `amount`:

```typescript
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

The broken value propagates to two security-relevant surfaces:

**1. NFTOfferEditor (offer creation):** `nftSellerNetAmount` drives both the "You will receive" label and the `showNegativeAmountWarning` guard. Because `nftSellerNetAmount` always equals `amount` (always positive), the guard can never fire even when the royalty percentage exceeds 100 % and the seller's actual proceeds would be zero or negative. [2](#0-1) 

**2. NFTOfferViewer (offer acceptance):** `overrideNFTSellerAmount` is derived from `nftSaleInfo?.nftSellerNetAmount` and passed through `NFTOfferSummary` → `OfferSummaryTokenRow`, where it replaces the raw on-chain amount shown to the accepting party. Because `nftSellerNetAmount = amount`, the "Net Proceeds" line always shows the full asking price rather than the post-royalty net. [3](#0-2) [4](#0-3) 

### Impact Explanation
A seller creating an offer for an NFT with a high royalty (e.g., 90 %) sees "You will receive: 100 XCH" when they will actually receive 10 XCH. The guard that should warn them ("Unable to create an offer where the net amount is negative") is permanently suppressed because `nftSellerNetAmount` is always positive. The seller signs and submits the offer under a false belief about their proceeds — displaying the wrong amount in the offer confirmation flow and bypassing the only in-GUI protection against royalty-induced zero-proceeds offers.

### Likelihood Explanation
Any NFT with a non-zero `royaltyPercentage` triggers the wrong display. The attacker path requires no special privileges: an attacker mints an NFT with a high royalty percentage, sells it to a victim, and the victim — when they later try to re-sell — is shown inflated net proceeds and receives no warning even if royalties would consume the entire asking price.

### Recommendation
Restore the commented-out formula in `calculateNFTRoyalties`:

```typescript
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
``` [5](#0-4) 

### Proof of Concept
1. Mint an NFT with `royalty_percentage = 9000` (90 %).
2. Open the NFT Offer Editor, select "Sell an NFT", enter the NFT ID, and set the asking price to 10 XCH.
3. The UI shows "You will receive: 10 XCH" and "Creator Fee: 9 XCH" — the "Net Proceeds" field should show 1 XCH but shows 10 XCH.
4. Set `royalty_percentage = 10001` (> 100 %): the negative-amount warning still never appears.
5. The seller signs and submits the offer; the blockchain correctly pays the creator and leaves the seller with far less (or nothing) compared to what the GUI displayed.

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

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L364-372)
```typescript
                  <Typography variant="subtitle1" color={showNegativeAmountWarning ? StateColor.ERROR : 'inherit'}>
                    <FormatLargeNumber value={new BigNumber(nftSellerNetAmount ?? 0)} />{' '}
                    {tokenWalletInfo.symbol ?? tokenWalletInfo.name ?? ''}
                  </Typography>
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

**File:** packages/gui/src/components/offers/OfferSummaryRow.tsx (L143-149)
```typescript
  const { assetId, amount: originalAmount, rowNumber, overrideNFTSellerAmount } = props;
  const { lookupByAssetId } = useAssetIdName();
  const assetIdInfo = lookupByAssetId(assetId);
  const amount = overrideNFTSellerAmount ?? originalAmount;
  const displayAmount = assetIdInfo
    ? formatAmountForWalletType(amount as number, assetIdInfo.walletType)
    : mojoToCATLocaleString(amount);
```
