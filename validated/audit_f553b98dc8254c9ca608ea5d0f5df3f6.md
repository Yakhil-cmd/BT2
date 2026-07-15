Now I have the complete picture. Let me trace the full chain:

1. `calculateNFTRoyalties` sets `nftSellerNetAmount = amount` (line 314) — the commented-out correct formula was `amount - royaltyAmount - makerFee`
2. `NFTOfferViewer.tsx` computes `overrideNFTSellerAmount = chiaToMojo(nftSaleInfo?.nftSellerNetAmount)` — which equals the full offered amount, not the net after royalties
3. `OfferSummaryTokenRow` uses `const amount = overrideNFTSellerAmount ?? originalAmount` — replacing the displayed amount with the wrong value
4. The "You will receive" label in the offer acceptance UI shows the inflated amount to the NFT seller

This is a valid analog. Here is the full report:

---

### Title
Incorrect `nftSellerNetAmount` in `calculateNFTRoyalties` causes NFT offer viewer to display inflated "You will receive" amount, misleading NFT sellers into accepting unfavorable offers - (File: `packages/gui/src/components/offers/utils.ts`)

### Summary
`calculateNFTRoyalties` in `packages/gui/src/components/offers/utils.ts` unconditionally sets `nftSellerNetAmount = amount` (line 314), ignoring royalties. The commented-out code directly below shows the correct formula was `amount - royaltyAmount - makerFee`. This wrong value propagates through `NFTOfferViewer.tsx` into `OfferSummaryTokenRow`, where it overrides the displayed token amount under the "You will receive" heading that an NFT seller sees before accepting a `TokenForNFT` offer. The seller is shown the full offered amount rather than the net proceeds after royalties, causing them to accept offers under false pretenses.

### Finding Description
In `calculateNFTRoyalties`:

```typescript
// packages/gui/src/components/offers/utils.ts, line 314
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

The correct value for `TokenForNFT` is `amount - royaltyAmount`, because in that exchange type the royalty is paid from the offered purchase price (as stated in the UI tooltip: *"those creator fees will be paid from the offered purchase price"*). The NFT seller therefore receives less than the full offered amount.

This wrong value is consumed in `NFTOfferViewer.tsx`:

```typescript
// packages/gui/src/components/offers/NFTOfferViewer.tsx, lines 397-402
const overrideNFTSellerAmount =
  exchangeType === NFTOfferExchangeType.TokenForNFT
    ? assetType === OfferAsset.CHIA
      ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)   // ← wrong: equals full amount
      : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
    : undefined;
``` [2](#0-1) 

`overrideNFTSellerAmount` is passed down through `NFTOfferSummary` → `NFTOfferSummaryRow` → `OfferSummaryTokenRow`, where it replaces the displayed amount:

```typescript
// packages/gui/src/components/offers/OfferSummaryRow.tsx, line 146
const amount = overrideNFTSellerAmount ?? originalAmount;
``` [3](#0-2) 

The `makerTitle` passed to `NFTOfferSummary` in the offer acceptance view is **"You will receive"**: [4](#0-3) 

So the NFT seller, when viewing an imported `TokenForNFT` offer to decide whether to accept it, sees "You will receive: 100 XCH" when they will actually receive 90 XCH (after a 10% royalty). The "Net Proceeds" field at the bottom of the same view is also wrong for the same reason: [5](#0-4) 

### Impact Explanation
An NFT seller who imports a `TokenForNFT` offer and views it in `NFTOfferDetails` is shown an inflated "You will receive" amount and an inflated "Net Proceeds" figure. Both are derived from the incorrect `nftSellerNetAmount`. The seller may accept the offer believing they will receive the full offered amount, when in reality they receive `amount - royaltyAmount`. For NFTs with high royalty percentages (the UI already warns at ≥ 20%), the discrepancy can be substantial. This constitutes displaying the wrong amount in the offer acceptance flow, causing a user to approve a transaction for the wrong amount — a direct financial loss to the NFT seller.

### Likelihood Explanation
This triggers for every `TokenForNFT` offer involving an NFT that has a non-zero `royaltyPercentage`. No special attacker capability is required: any buyer can create such an offer and share it. The NFT seller is an unprivileged user who views the offer through the standard import flow. The bug is deterministic and reproducible.

### Recommendation
In `calculateNFTRoyalties`, restore the correct conditional calculation for `nftSellerNetAmount`:

```typescript
const nftSellerNetAmount: number =
  exchangeType === NFTOfferExchangeType.TokenForNFT
    ? parseFloat((amount - parseFloat(royaltyAmountString)).toFixed(12))
    : amount;
``` [6](#0-5) 

### Proof of Concept
1. Mint an NFT with a 10% royalty.
2. A buyer creates a `TokenForNFT` offer: offer 100 XCH, request the NFT.
3. The NFT seller imports the offer file into the GUI.
4. In the offer viewer (`NFTOfferDetails`), the "You will receive" row shows **100 XCH** and "Net Proceeds" shows **100 XCH**.
5. The seller accepts the offer.
6. On-chain, the royalty (10 XCH) is deducted from the offered amount; the seller receives **90 XCH**, not 100 XCH.
7. The discrepancy is caused by `nftSellerNetAmount = amount` (line 314 of `utils.ts`) instead of `amount - royaltyAmount`.

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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L397-402)
```typescript
  const overrideNFTSellerAmount =
    exchangeType === NFTOfferExchangeType.TokenForNFT
      ? assetType === OfferAsset.CHIA
        ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
        : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : undefined;
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L476-490)
```typescript
                makerTitle={
                  <Typography variant="body1" color="textSecondary">
                    <Trans>You will receive</Trans>
                  </Typography>
                }
                takerTitle={
                  <Typography variant="body1" color="textSecondary">
                    <Trans>In exchange for</Trans>
                  </Typography>
                }
                setIsMissingRequestedAsset={(isMissing: boolean) => setIsMissingRequestedAsset(isMissing)}
                rowIndentation={0}
                showNFTPreview={false}
                showMakerFee={false}
                overrideNFTSellerAmount={overrideNFTSellerAmount}
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
