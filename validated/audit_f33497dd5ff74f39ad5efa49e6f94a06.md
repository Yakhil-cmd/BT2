### Title
Wrong NFT Seller Net Proceeds Calculation Displays Inflated "You Will Receive" Amount in NFT Offer Flow - (File: packages/gui/src/components/offers/utils.ts)

### Summary
In `calculateNFTRoyalties`, `nftSellerNetAmount` is hardcoded to the full asking `amount` instead of `amount - royaltyAmount`. The correct subtraction formula is present but commented out. This causes the "You will receive" / "Net Proceeds" display to show the full asking price rather than the actual net amount after creator royalties are deducted, misleading NFT sellers about their actual proceeds when creating or reviewing offers.

### Finding Description
In `packages/gui/src/components/offers/utils.ts`, the `calculateNFTRoyalties` function computes `nftSellerNetAmount` as simply `amount` (the full asking price), with the correct subtraction formula explicitly commented out:

```typescript
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

The correct value should be `amount - royaltyAmount`. This `nftSellerNetAmount` is then consumed in two places:

1. **NFT Offer Editor** (`NFTOfferEditor.tsx` line 365): displayed as "You will receive" (when selling an NFT) or "They will receive" (when buying an NFT), directly under the royalty breakdown. [2](#0-1) 

2. **NFT Offer Viewer** (`NFTOfferViewer.tsx` line 596): displayed as "Net Proceeds" in the offer details panel, with a tooltip explicitly stating "The net proceeds include the asking price, minus any associated creator fees." [3](#0-2) 

Additionally, `nftSellerNetAmount` is converted to mojos and passed as `overrideNFTSellerAmount` to `NFTOfferSummary` → `NFTOfferSummaryRow` → `OfferSummaryTokenRow`, where it overrides the displayed token amount in the "You will receive" summary row for the NFT seller side. [4](#0-3) 

The `showNegativeAmountWarning` guard in the editor (`nftSellerNetAmount < 0`) is also rendered ineffective because `nftSellerNetAmount` is always equal to `amount` (always positive), so the warning never fires even when the true net proceeds would be negative. [5](#0-4) 

### Impact Explanation
An NFT seller creating or reviewing an offer with royalties enabled sees an inflated "Net Proceeds" / "You will receive" amount equal to the full asking price. In reality, the seller receives the asking price minus the creator royalty. For example, with a 10% royalty on a 1 XCH offer, the seller sees "You will receive: 1 XCH" but actually receives 0.9 XCH. The label "Net Proceeds" with its tooltip ("minus any associated creator fees") explicitly promises the deducted value, but the displayed figure is wrong. This misleads the NFT seller into creating and signing offers based on incorrect financial information — they may set a price of 1 XCH intending to net 1 XCH, but actually net 0.9 XCH. This constitutes displaying the wrong amount in the offer approval flow, causing the user to sign/create an offer for the wrong effective proceeds.

**Impact: High** — wrong amount displayed in offer creation/review flow causes user to approve an offer based on incorrect net proceeds.

### Likelihood Explanation
Any NFT with `royaltyPercentage > 0` (which is common in the Chia NFT ecosystem — royalties are a core NFT feature) will trigger this bug whenever the NFT Offer Editor or Viewer is used. The path is fully reachable by any unprivileged user who creates or views an NFT offer.

### Recommendation
Restore the correct `nftSellerNetAmount` calculation in `calculateNFTRoyalties`:

```typescript
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString)).toFixed(12),
);
``` [6](#0-5) 

### Proof of Concept
1. Open the Chia GUI and navigate to the NFT Offer Editor.
2. Select "Sell an NFT" tab.
3. Enter an NFT ID for an NFT with a 10% royalty (`royaltyPercentage = 1000` in raw units).
4. Enter an asking price of 1 XCH.
5. Observe: "Creator Fee (10%): 0.1 XCH" is shown correctly.
6. Observe: "You will receive: 1 XCH" — **this is wrong**; the correct value is 0.9 XCH.
7. The seller creates and signs the offer believing they will net 1 XCH, but the blockchain correctly deducts 0.1 XCH as royalty, leaving the seller with 0.9 XCH.
8. The same wrong value appears in `NFTOfferViewer.tsx` under "Net Proceeds" when the offer is viewed by either party.

### Citations

**File:** packages/gui/src/components/offers/utils.ts (L306-329)
```typescript
export function calculateNFTRoyalties(
  amount: number,
  makerFee: number,
  royaltyPercentage: number,
  exchangeType: NFTOfferExchangeType,
): CalculateNFTRoyaltiesResult {
  const royaltyAmount: number = royaltyPercentage ? (royaltyPercentage / 100) * amount : 0;
  const royaltyAmountString: string = formatAmount(royaltyAmount);
  const nftSellerNetAmount: number = amount;
  // : parseFloat(
  //     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
  //   );
  const totalAmount: number =
    exchangeType === NFTOfferExchangeType.NFTForToken ? amount + royaltyAmount : amount + makerFee + royaltyAmount;
  const totalAmountString: string = formatAmount(totalAmount);

  return {
    royaltyAmount,
    royaltyAmountString,
    nftSellerNetAmount,
    totalAmount,
    totalAmountString,
  };
}
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L271-271)
```typescript
  const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L357-367)
```typescript
                  <Typography variant="body1" color="textSecondary">
                    {tab === NFTOfferExchangeType.NFTForToken ? (
                      <Trans>You will receive</Trans>
                    ) : (
                      <Trans>They will receive</Trans>
                    )}
                  </Typography>
                  <Typography variant="subtitle1" color={showNegativeAmountWarning ? StateColor.ERROR : 'inherit'}>
                    <FormatLargeNumber value={new BigNumber(nftSellerNetAmount ?? 0)} />{' '}
                    {tokenWalletInfo.symbol ?? tokenWalletInfo.name ?? ''}
                  </Typography>
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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L580-598)
```typescript
                  {exchangeType === NFTOfferExchangeType.TokenForNFT && (
                    <Flex flexDirection="column" gap={0.5}>
                      <Flex flexDirection="row" alignItems="center" gap={1}>
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
                    </Flex>
```
