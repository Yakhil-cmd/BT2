### Title
`calculateNFTRoyalties` Returns Incorrect `nftSellerNetAmount`, Causing NFT Offer Viewer to Display Wrong "Net Proceeds" and "You Will Receive" Amounts to Accepting Party - (File: packages/gui/src/components/offers/utils.ts)

### Summary

`calculateNFTRoyalties` in `packages/gui/src/components/offers/utils.ts` hard-codes `nftSellerNetAmount = amount` (the full offered amount) with the correct subtraction of royalties commented out. This value is propagated into the NFT offer viewer as `overrideNFTSellerAmount` and displayed as both "You will receive" and "Net Proceeds" to the NFT seller when they are about to accept a `TokenForNFT` offer. The seller is shown the full offered amount rather than the amount they will actually receive after royalties are deducted, causing them to approve an offer based on a materially incorrect figure.

### Finding Description

In `calculateNFTRoyalties`:

```typescript
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
```

`nftSellerNetAmount` is unconditionally set to `amount` (the gross offered amount). The correct calculation — subtracting `royaltyAmountString` — is commented out. [1](#0-0) 

This value flows into `NFTOfferDetails` in `NFTOfferViewer.tsx`, where it is converted back to mojos and used as `overrideNFTSellerAmount`:

```typescript
const overrideNFTSellerAmount =
  exchangeType === NFTOfferExchangeType.TokenForNFT
    ? assetType === OfferAsset.CHIA
      ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
    : undefined;
``` [2](#0-1) 

`overrideNFTSellerAmount` is passed to `NFTOfferSummary` → `NFTOfferSummaryRow` → `OfferSummaryTokenRow`, where it replaces the displayed token amount:

```typescript
const amount = overrideNFTSellerAmount ?? originalAmount;
``` [3](#0-2) 

The same incorrect `nftSellerNetAmount` is also rendered directly as the "Net Proceeds" label in the offer detail panel, whose tooltip explicitly states it should show "the asking price, minus any associated creator fees": [4](#0-3) 

Additionally, the `totalAmount` calculation for `TokenForNFT` adds royalties on top of the offered amount (`amount + makerFee + royaltyAmount`) rather than treating royalties as paid from within the offered amount, producing a further incorrect "Total Amount Offered" figure: [5](#0-4) 

### Impact Explanation

When an NFT seller opens an imported `TokenForNFT` offer to accept it, the GUI shows:

| Label | Displayed | Correct |
|---|---|---|
| "You will receive" | 10 XCH (full offered amount) | 9 XCH (after 10% royalty) |
| "Net Proceeds" | 10 XCH | 9 XCH |
| "Total Amount Offered" | 11 XCH | 10 XCH |

The seller clicks **Accept** believing they will receive 10 XCH but actually receives 9 XCH. The protocol enforces the correct royalty split on-chain; the GUI simply misrepresents it. This constitutes displaying the wrong amount in the offer confirmation flow, causing the user to approve an offer based on materially incorrect financial information.

### Likelihood Explanation

Any `TokenForNFT` offer involving an NFT with a non-zero `royaltyPercentage` triggers this path. This is a common case — royalties are a standard NFT feature. Any NFT seller who views and accepts such an offer via the GUI is affected. No special attacker action is required; the bug is structural in the shared `calculateNFTRoyalties` utility.

### Recommendation

Restore the correct `nftSellerNetAmount` calculation in `calculateNFTRoyalties`:

```typescript
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString)).toFixed(12),
);
```

Note: the original commented-out code also subtracted `makerFee`, which is incorrect — the maker fee is paid by the offer creator, not deducted from the seller's proceeds. Only `royaltyAmountString` should be subtracted.

Also fix `totalAmount` for `TokenForNFT`: royalties are paid from within the offered amount, so `totalAmount` should equal `amount + makerFee` (not `amount + makerFee + royaltyAmount`).

### Proof of Concept

1. Create a `TokenForNFT` offer: buyer offers 10 XCH for an NFT with 10% royalty.
2. Share the offer string with the NFT seller.
3. NFT seller opens the offer in the GUI (`NFTOfferViewer`).
4. Observe: "You will receive: 10 XCH", "Net Proceeds: 10 XCH", "Total Amount Offered: 11 XCH".
5. Seller accepts. On-chain result: seller receives 9 XCH, royalty recipient receives 1 XCH.
6. The seller received 10% less than the GUI indicated at the point of approval.

### Citations

**File:** packages/gui/src/components/offers/utils.ts (L314-317)
```typescript
  const nftSellerNetAmount: number = amount;
  // : parseFloat(
  //     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
  //   );
```

**File:** packages/gui/src/components/offers/utils.ts (L318-320)
```typescript
  const totalAmount: number =
    exchangeType === NFTOfferExchangeType.NFTForToken ? amount + royaltyAmount : amount + makerFee + royaltyAmount;
  const totalAmountString: string = formatAmount(totalAmount);
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

**File:** packages/gui/src/components/offers/OfferSummaryRow.tsx (L146-146)
```typescript
  const amount = overrideNFTSellerAmount ?? originalAmount;
```
