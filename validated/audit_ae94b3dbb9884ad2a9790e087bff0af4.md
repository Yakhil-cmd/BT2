### Title
NFT Offer "Net Proceeds" Omits Royalty Deduction, Misleading NFT Sellers Into Accepting Offers - (File: packages/gui/src/components/offers/utils.ts)

### Summary
`calculateNFTRoyalties` sets `nftSellerNetAmount = amount` (the full offered price) instead of `amount - royaltyAmount`. The "Net Proceeds" label displayed to an NFT seller when reviewing a `TokenForNFT` offer therefore shows an inflated figure — identical to the raw offer amount — even though the tooltip explicitly promises it reflects the asking price *minus* creator fees. An unprivileged buyer can exploit this by creating a `TokenForNFT` offer for an NFT with non-trivial royalties; the seller sees a flattering "Net Proceeds" and accepts, but receives materially less than displayed.

### Finding Description

`calculateNFTRoyalties` in `packages/gui/src/components/offers/utils.ts` computes three output values: `royaltyAmount`, `totalAmount`, and `nftSellerNetAmount`. The royalty deduction is correctly applied to `totalAmount`, but the commented-out subtraction for `nftSellerNetAmount` was never restored:

```js
// packages/gui/src/components/offers/utils.ts  lines 312-317
const royaltyAmount: number = royaltyPercentage ? (royaltyPercentage / 100) * amount : 0;
const royaltyAmountString: string = formatAmount(royaltyAmount);
const nftSellerNetAmount: number = amount;          // ← royaltyAmount never subtracted
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

`nftSellerNetAmount` is consumed in two places:

1. **`NFTOfferViewer.tsx` — the offer-acceptance screen** (the critical path). For a `TokenForNFT` offer the viewer renders a prominent "Net Proceeds" heading whose tooltip reads *"The net proceeds include the asking price, minus any associated creator fees"*, but the value rendered is `nftSaleInfo?.nftSellerNetAmount` — which equals the raw `amount`, not `amount − royaltyAmount`. [2](#0-1) [3](#0-2) 

2. **`NFTOfferEditor.tsx` — the offer-creation screen**. For the `TokenForNFT` tab the editor shows "They will receive" using the same `nftSellerNetAmount`, again without the royalty deduction. [4](#0-3) 

The `overrideNFTSellerAmount` derived from `nftSellerNetAmount` is also passed into `NFTOfferSummary` to override the amount shown in the "You will receive" summary panel, propagating the inflated figure throughout the acceptance UI. [5](#0-4) 

### Impact Explanation

For a `TokenForNFT` offer where the NFT carries a 10 % royalty and the buyer offers 100 XCH:

| Label shown in GUI | Value displayed | Correct value |
|---|---|---|
| NFT Purchase Price | 100 XCH | 100 XCH |
| Creator Fee (10%) | 10 XCH | 10 XCH |
| **Net Proceeds** | **100 XCH** | **90 XCH** |

The NFT seller reads "Net Proceeds: 100 XCH", trusts the label (which the tooltip explicitly defines as post-royalty), and accepts. They receive 90 XCH. The discrepancy scales linearly with royalty percentage and offer size. For NFTs with 20 %+ royalties (the threshold at which the GUI already shows a warning) the seller receives ≤ 80 % of the displayed "Net Proceeds".

This fits the allowed High impact: *"unsafe trust of … offer … state that causes a user to … display the wrong … amount … or status"* and causes the user to *approve* (accept) an offer based on a materially incorrect amount.

### Likelihood Explanation

Any unprivileged actor can create a `TokenForNFT` offer for any NFT. The bug is triggered whenever the NFT has a non-zero `royaltyPercentage` — a common property for NFTs minted with creator royalties. No special access, leaked keys, or social engineering is required; the victim only needs to open the offer in the GUI and read the "Net Proceeds" figure.

### Recommendation

Restore the royalty deduction in `calculateNFTRoyalties`, conditioned on exchange type (royalties are borne by the taker in `TokenForNFT`):

```diff
- const nftSellerNetAmount: number = amount;
+ const nftSellerNetAmount: number =
+   exchangeType === NFTOfferExchangeType.TokenForNFT
+     ? parseFloat((amount - parseFloat(royaltyAmountString)).toFixed(12))
+     : amount;
``` [6](#0-5) 

### Proof of Concept

1. Open the Chia GUI and navigate to **Offers → View Offer File**.
2. Import a `TokenForNFT` offer file for an NFT whose `royaltyPercentage > 0` (e.g., 10 %).
3. Observe the **Net Proceeds** field: it displays the full offered token amount (e.g., 100 XCH).
4. Read the tooltip: *"The net proceeds include the asking price, minus any associated creator fees."*
5. Accept the offer.
6. Observe the actual received amount in wallet history: 90 XCH (100 − 10 % royalty).

The displayed "Net Proceeds" (100 XCH) exceeds the actual received amount (90 XCH) by exactly `royaltyAmount`, confirming the missing deduction in `calculateNFTRoyalties`. [7](#0-6) [8](#0-7)

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
