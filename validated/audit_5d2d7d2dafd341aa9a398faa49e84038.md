### Title
Incorrect Net Proceeds Display Due to Commented-Out Royalty Deduction in NFT Offer Viewer — (File: `packages/gui/src/components/offers/utils.ts`)

---

### Summary

`calculateNFTRoyalties` in `utils.ts` sets `nftSellerNetAmount` to the raw offer amount instead of `amount − royaltyAmount`. The correct subtraction is present but commented out. `NFTOfferViewer.tsx` consumes this value and renders it under the label **"Net Proceeds"** with a tooltip that explicitly promises royalties have been deducted. An NFT seller viewing an imported `TokenForNFT` offer therefore sees a higher figure than they will actually receive on-chain, and may accept an offer they would otherwise reject.

---

### Finding Description

In `packages/gui/src/components/offers/utils.ts`, `calculateNFTRoyalties` computes the royalty amount correctly but then assigns the full, unmodified `amount` to `nftSellerNetAmount`:

```typescript
// packages/gui/src/components/offers/utils.ts  lines 312-317
const royaltyAmount: number = royaltyPercentage ? (royaltyPercentage / 100) * amount : 0;
const royaltyAmountString: string = formatAmount(royaltyAmount);
const nftSellerNetAmount: number = amount;          // ← BUG: should be amount − royaltyAmount
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

`NFTOfferViewer.tsx` calls `calculateNFTRoyalties` and then renders `nftSaleInfo.nftSellerNetAmount` as the **"Net Proceeds"** figure, exclusively in the `TokenForNFT` branch (where the viewer is the NFT seller accepting a token-for-NFT offer):

```typescript
// NFTOfferViewer.tsx  lines 595-597
<Typography variant="h5" fontWeight="bold">
  <FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} /> {displayName}
</Typography>
``` [2](#0-1) 

The accompanying tooltip reads: *"The net proceeds include the asking price, **minus any associated creator fees**"* — but the displayed value is the full asking price with no royalty deducted. [3](#0-2) 

The same erroneous `nftSellerNetAmount` is also converted back to mojos and passed as `overrideNFTSellerAmount` to `NFTOfferSummary`, which forwards it to `OfferSummaryTokenRow` to override the displayed token amount in the "You will receive" row:

```typescript
// NFTOfferViewer.tsx  lines 397-402
const overrideNFTSellerAmount =
    exchangeType === NFTOfferExchangeType.TokenForNFT
      ? assetType === OfferAsset.CHIA
        ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)   // full amount, not net
        : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : undefined;
``` [4](#0-3) 

Because `nftSellerNetAmount === amount`, `overrideNFTSellerAmount` equals the original mojo value from the offer summary, so the "You will receive" row is unchanged. The sole concrete discrepancy visible to the user is the **"Net Proceeds"** figure, which omits the royalty deduction.

---

### Impact Explanation

When an NFT seller opens an imported `TokenForNFT` offer in `NFTOfferDetails`, the UI prominently displays a "Net Proceeds" figure that equals the full offer amount. The tooltip explicitly states royalties are subtracted, so the user has every reason to trust this number as their actual take-home. If the NFT carries a non-trivial royalty (e.g., 10 %), the displayed "Net Proceeds" overstates the real payout by `royaltyPercentage / 100 × amount`. The user may accept the offer on the basis of this inflated figure, receiving materially less XCH or CAT than they believed they agreed to. This satisfies the **High** impact criterion: the offer confirmation screen displays the wrong amount, causing the user to approve a transaction whose real payout differs from what is shown.

---

### Likelihood Explanation

Any NFT with a non-zero `royaltyPercentage` triggers this path. The `TokenForNFT` viewer flow is a standard, documented user journey (accepting an offer to sell your NFT). No special attacker capability is required — the bug is triggered by the normal offer-viewing flow for any royalty-bearing NFT offer. An adversary who knows about this bug can craft an offer with a high royalty percentage, confident the seller will see an inflated "Net Proceeds" and accept.

---

### Recommendation

In `calculateNFTRoyalties`, restore the deduction so `nftSellerNetAmount` reflects actual proceeds:

```typescript
// packages/gui/src/components/offers/utils.ts
const nftSellerNetAmount: number = parseFloat(
  (amount - royaltyAmount).toFixed(12)
);
```

The `makerFee` subtraction in the commented-out code is incorrect for the `TokenForNFT` case (the maker fee is borne by the offer creator, not the NFT seller), so only `royaltyAmount` should be subtracted.

---

### Proof of Concept

1. Create a `TokenForNFT` offer for an NFT with `royaltyPercentage = 1000` (10 %) and a token amount of 100 XCH.
2. Import the offer file into a second wallet that owns the NFT.
3. Open the offer in `NFTOfferDetails` (the `NFTOfferViewer` path).
4. Observe: **"Net Proceeds"** displays **100 XCH** with the tooltip "minus any associated creator fees".
5. Actual on-chain payout to the NFT seller: **90 XCH** (10 XCH goes to the royalty address).
6. The discrepancy is `royaltyAmount = (royaltyPercentage / 100) * amount = 10 XCH`, exactly the value that `calculateNFTRoyalties` computes correctly for `royaltyAmountString` but fails to subtract from `nftSellerNetAmount`. [5](#0-4) [6](#0-5)

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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L377-402)
```typescript
  const nftSaleInfo = useMemo(() => {
    if (!exchangeType || amount === undefined || !nft || nft.royaltyPercentage === undefined) {
      return undefined;
    }

    const royaltyPercentage = convertRoyaltyToPercentage(nft.royaltyPercentage);
    const xchMakerFee = mojoToChia(makerFee);

    return {
      ...calculateNFTRoyalties(
        amount,
        parseFloat(xchMakerFee),
        convertRoyaltyToPercentage(nft.royaltyPercentage),
        exchangeType,
      ),
      royaltyPercentage,
    };
  }, [amount, exchangeType, makerFee, nft]);
  const showRoyaltyWarning = (nftSaleInfo?.royaltyPercentage ?? 0) >= 20;
  const royaltyPercentageColor = showRoyaltyWarning ? StateColor.WARNING : 'textSecondary';
  const overrideNFTSellerAmount =
    exchangeType === NFTOfferExchangeType.TokenForNFT
      ? assetType === OfferAsset.CHIA
        ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
        : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : undefined;
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L580-597)
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
```
