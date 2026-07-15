### Title
`calculateNFTRoyalties`: NFT Seller "Net Proceeds" and "You Will Receive" Amounts Overstate Actual Payout When Accepting a TokenForNFT Offer — (`packages/gui/src/components/offers/utils.ts`, `packages/gui/src/components/offers/NFTOfferViewer.tsx`)

---

### Summary

In the NFT offer viewer, when a buyer-created (`TokenForNFT`) offer is displayed to the NFT seller for acceptance, the GUI shows the full offered token amount as both "Net Proceeds" and "You will receive." In reality, the NFT seller receives `amount − royaltyAmount` because creator royalties are paid from the offered price. The discrepancy is baked into `calculateNFTRoyalties`, which hard-codes `nftSellerNetAmount = amount` regardless of exchange type, with the correct subtraction commented out. An unprivileged buyer can exploit this to induce an NFT seller to accept an offer for less than the seller believes they will receive.

---

### Finding Description

In `packages/gui/src/components/offers/utils.ts`, `calculateNFTRoyalties` always sets:

```typescript
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

The commented-out branch was the correct computation for the `TokenForNFT` case. As a result, `nftSellerNetAmount` always equals the raw offered `amount`, never subtracting the royalty.

In `NFTOfferViewer.tsx`, `NFTOfferDetails` computes `nftSaleInfo` via `calculateNFTRoyalties` and then:

1. Derives `overrideNFTSellerAmount = chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)` — the full `amount` in mojos — and passes it to `NFTOfferSummary` under the label **"You will receive"**. [2](#0-1) 

2. Renders a **"Net Proceeds"** row with `nftSaleInfo?.nftSellerNetAmount` and a tooltip that reads *"The net proceeds include the asking price, minus any associated creator fees"* — but the value displayed is the full `amount`, not `amount − royaltyAmount`. [3](#0-2) 

The tooltip for the `TokenForNFT` total correctly states *"those creator fees will be paid from the offered purchase price"*, confirming the protocol deducts royalties from the offered amount before paying the seller. [4](#0-3) 

The same stale `nftSellerNetAmount = amount` value is also used in `NFTOfferEditor.tsx` under the **"They will receive"** label when a buyer is composing a `TokenForNFT` offer. [5](#0-4) 

---

### Impact Explanation

An NFT seller who opens an imported `TokenForNFT` offer sees:

- **"You will receive: X XCH"** (full offered amount)
- **"Net Proceeds: X XCH"** (same full amount, tooltip claims royalties are subtracted)

The seller actually receives `X − royaltyAmount` XCH after the protocol deducts creator royalties from the offered price. For an NFT with a 10 % royalty and an offer of 10 XCH, the seller receives 9 XCH while the GUI shows 10 XCH on both lines. The seller approves the offer based on a materially incorrect amount display, resulting in a direct, unrecoverable asset shortfall.

This satisfies the **High** impact criterion: the offer state causes a user to accept (approve) the wrong amount for their NFT.

---

### Likelihood Explanation

Any unprivileged actor can create a `TokenForNFT` offer for any NFT that has a non-zero `royaltyPercentage`. The NFT seller need only open the offer file in the GUI. No leaked keys, host compromise, or social engineering beyond sharing a standard offer file is required. The higher the royalty percentage, the larger the gap between the displayed and actual proceeds.

---

### Recommendation

In `calculateNFTRoyalties`, restore the correct `nftSellerNetAmount` for the `TokenForNFT` case:

```typescript
const nftSellerNetAmount: number =
  exchangeType === NFTOfferExchangeType.TokenForNFT
    ? parseFloat((amount - parseFloat(royaltyAmountString)).toFixed(12))
    : amount;
``` [6](#0-5) 

Additionally, ensure `overrideNFTSellerAmount` in `NFTOfferViewer` is derived from the corrected `nftSellerNetAmount` so that both the "You will receive" row and the "Net Proceeds" row reflect the actual post-royalty payout. [7](#0-6) 

---

### Proof of Concept

1. Mint an NFT with `royaltyPercentage = 1000` (10 %).
2. As an unprivileged buyer, create a `TokenForNFT` offer for 10 XCH and export the `.offer` file.
3. As the NFT seller, import the offer file into the GUI.
4. Observe: **"You will receive: 10 XCH"** and **"Net Proceeds: 10 XCH"** are both displayed.
5. Accept the offer.
6. Observe on-chain: seller receives **9 XCH**; 1 XCH goes to the royalty address.

The 1 XCH shortfall is invisible to the seller at approval time because `nftSellerNetAmount` is never reduced by `royaltyAmount` in `calculateNFTRoyalties`. [8](#0-7)

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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L561-569)
```typescript
                          ) : (
                            <Trans>
                              The total amount offered includes the offered purchase price, plus the optional offer
                              creation fee.
                              <p />
                              If the NFT has royalty payments enabled, those creator fees will be paid from the offered
                              purchase price.
                            </Trans>
                          )}
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
