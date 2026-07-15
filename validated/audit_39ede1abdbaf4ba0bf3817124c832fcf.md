I have enough information to write the finding. The key code is in `calculateNFTRoyalties` and how `nftSellerNetAmount` flows through the offer viewer and summary.

### Title
NFT Offer "Net Proceeds" and Offer Summary Display Incorrect Amount Due to Missing Royalty Deduction in `calculateNFTRoyalties` - (File: `packages/gui/src/components/offers/utils.ts`)

### Summary
`calculateNFTRoyalties` hardcodes `nftSellerNetAmount = amount` (the full offered amount) instead of `amount - royaltyAmount`. This causes both the "Net Proceeds" label and the offer summary's "You will receive" row to display the full pre-royalty amount to an NFT seller reviewing a `TokenForNFT` offer, while the actual on-chain settlement deducts the royalty from that amount. The seller is shown a materially higher figure than they will actually receive, causing them to approve the wrong amount.

### Finding Description

In `packages/gui/src/components/offers/utils.ts`, `calculateNFTRoyalties` computes:

```typescript
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
```

The commented-out block is the original intended formula. The current code unconditionally assigns `nftSellerNetAmount = amount`, ignoring royalties entirely. [1](#0-0) 

This value propagates in two ways:

**1. "Net Proceeds" label in `NFTOfferViewer.tsx`** — shown only for `TokenForNFT` (buyer-created offer), with the tooltip explicitly stating *"The net proceeds include the asking price, minus any associated creator fees"*. Because `nftSellerNetAmount = amount`, the displayed value never subtracts royalties. [2](#0-1) 

**2. `overrideNFTSellerAmount` in the offer summary row** — `NFTOfferDetails` converts `nftSellerNetAmount` to mojos and passes it as `overrideNFTSellerAmount` to `NFTOfferSummary` → `NFTOfferSummaryRow` → `OfferSummaryTokenRow`, where:

```typescript
const amount = overrideNFTSellerAmount ?? originalAmount;
``` [3](#0-2) [4](#0-3) 

The intent of `overrideNFTSellerAmount` is to replace the raw on-chain amount with the net-of-royalty figure. Because `nftSellerNetAmount` equals the full amount, the override has no corrective effect — the "You will receive" row in the Purchase Summary continues to show the full pre-royalty amount.

**3. Broken negative-amount guard in `NFTOfferEditor.tsx`** — `showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0` can never be true since `nftSellerNetAmount` is always the positive `amount`. The UI guard that is supposed to block creation of offers where royalties exceed the offered amount is permanently disabled. [5](#0-4) 

### Impact Explanation

When an NFT seller opens an imported `TokenForNFT` offer for an NFT with royalties, the GUI shows:

- **"You will receive: 100 XCH"** (offer summary row, overridden by `overrideNFTSellerAmount`)
- **"Net Proceeds: 100 XCH"** (dedicated label with tooltip promising royalty deduction)

The actual settlement delivers **80 XCH** (after a 20% royalty). The seller approves the offer based on a displayed receive-amount that is 25% higher than reality. This is a direct instance of the allowed High impact: *"causes a user to approve … the wrong … amount."*

### Likelihood Explanation

Any `TokenForNFT` offer involving an NFT with a non-zero `royaltyPercentage` triggers the incorrect display. No special attacker action is required beyond creating a standard buyer-side offer. The seller's only mitigation is to manually subtract the separately-displayed "Creator Fee" from the offered amount — a step the "Net Proceeds" label is specifically designed to perform for them, but does not.

### Recommendation

Restore the royalty deduction in `calculateNFTRoyalties`:

```typescript
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
```

Apply this only for the `TokenForNFT` exchange type (where royalties are paid from the offered amount), and keep `nftSellerNetAmount = amount` for `NFTForToken` (where the buyer pays royalties on top).

### Proof of Concept

1. Mint an NFT with `royaltyPercentage = 2000` (20%).
2. A buyer creates a `TokenForNFT` offer: 100 XCH for the NFT.
3. The NFT seller opens the imported offer in the GUI.
4. GUI displays: **"Net Proceeds: 100 XCH"** and **"You will receive: 100 XCH"**.
5. Seller accepts the offer.
6. On-chain settlement: 20 XCH → creator royalty address; **seller receives 80 XCH**.
7. Discrepancy: seller approved based on 100 XCH display, received 80 XCH — a 20 XCH shortfall driven entirely by the incorrect `nftSellerNetAmount = amount` assignment. [6](#0-5) [7](#0-6)

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

**File:** packages/gui/src/components/offers/OfferSummaryRow.tsx (L143-146)
```typescript
  const { assetId, amount: originalAmount, rowNumber, overrideNFTSellerAmount } = props;
  const { lookupByAssetId } = useAssetIdName();
  const assetIdInfo = lookupByAssetId(assetId);
  const amount = overrideNFTSellerAmount ?? originalAmount;
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L271-271)
```typescript
  const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
```
