Looking at the `calculateNFTRoyalties` function and how `nftSellerNetAmount` is used across the NFT offer flow.

### Title
Missing Royalty Deduction in `calculateNFTRoyalties` Causes Incorrect "Net Proceeds" Display in NFT Offer Viewer - (File: packages/gui/src/components/offers/utils.ts)

---

### Summary
`calculateNFTRoyalties` in `utils.ts` has a deliberately commented-out deduction that was supposed to compute the NFT seller's net proceeds after royalties. As a result, `nftSellerNetAmount` equals the full offered amount. The "Net Proceeds" field in `NFTOfferViewer.tsx` — whose own tooltip promises it shows "the asking price, minus any associated creator fees" — instead displays the full pre-royalty amount, misleading the NFT seller into believing they will receive more than they actually will when accepting a `TokenForNFT` offer.

---

### Finding Description

In `calculateNFTRoyalties`, the deduction is commented out:

```javascript
// packages/gui/src/components/offers/utils.ts
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

The intended value was `amount - royaltyAmount - makerFee`. The current code assigns the full `amount` unconditionally.

This incorrect value propagates to two distinct locations:

**1. "Net Proceeds" display in `NFTOfferViewer.tsx`**

The "Net Proceeds" section is rendered only for `TokenForNFT` offers (a buyer offering XCH/CAT to purchase the victim's NFT). Its tooltip explicitly states: *"The net proceeds include the asking price, minus any associated creator fees."* But the displayed value is `nftSaleInfo?.nftSellerNetAmount`, which equals the full offered amount — royalties are never subtracted. [2](#0-1) 

**2. Broken negative-amount guard in `NFTOfferEditor.tsx`**

The guard `showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0` is intended to warn a user when royalties exceed the asking price (making net proceeds negative). Because `nftSellerNetAmount` is always equal to the positive `amount`, this guard is permanently disabled. [3](#0-2) 

The `nftSaleInfo` object is computed in `NFTOfferViewer.tsx` by calling `calculateNFTRoyalties` and then used to derive `overrideNFTSellerAmount` (passed into the offer summary row) and the standalone "Net Proceeds" label: [4](#0-3) 

---

### Impact Explanation

When a victim (NFT seller) reviews a `TokenForNFT` offer in `NFTOfferDetails`, the GUI prominently shows:

- **"Net Proceeds: X XCH"** — with a tooltip promising this is the asking price *minus* creator fees.

Because `nftSellerNetAmount = amount` (missing the royalty deduction), the displayed value is the full offered amount. The victim accepts the offer expecting X XCH but actually receives `X − royalty` XCH. The royalty difference is paid directly to the NFT creator (the attacker). This fits the allowed High impact: *"Corruption, spoofing, or unsafe trust of… offer… state that causes a user to approve… the wrong… amount."*

The broken `showNegativeAmountWarning` guard is a secondary impact: a user creating an offer to sell an NFT where royalties exceed the asking price receives no warning and may unknowingly create an offer yielding zero or negative net proceeds. [5](#0-4) 

---

### Likelihood Explanation

Any NFT with a non-zero `royaltyPercentage` triggers this display bug. NFT royalties are a standard, widely-used feature of Chia NFTs. An attacker who minted an NFT with a high royalty (e.g., 30–50%) and sold it on a secondary market can then create a `TokenForNFT` offer to repurchase it, exploiting the wrong "Net Proceeds" display to cause the victim to accept without realizing the royalty deduction. No special privileges are required — minting an NFT on Chia is permissionless.

---

### Recommendation

Restore the commented-out deduction in `calculateNFTRoyalties`:

```javascript
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
``` [6](#0-5) 

This restores the correct net-proceeds computation, fixes the "Net Proceeds" display in `NFTOfferViewer.tsx`, and re-enables the `showNegativeAmountWarning` guard in `NFTOfferEditor.tsx`.

---

### Proof of Concept

1. Attacker mints a Chia NFT with `royaltyPercentage = 5000` (50%).
2. Attacker sells the NFT to a victim for 1 XCH on a secondary marketplace.
3. Attacker creates a `TokenForNFT` offer: *"I will pay 2 XCH for this NFT."*
4. Victim opens the offer in the Chia GUI. `NFTOfferDetails` calls:
   ```
   calculateNFTRoyalties(2, makerFee, 50, TokenForNFT)
   → royaltyAmount = 1 XCH
   → nftSellerNetAmount = 2 XCH  ← BUG: should be 1 XCH
   ```
5. The "Net Proceeds" field displays **"2 XCH"** with tooltip *"The net proceeds include the asking price, minus any associated creator fees."*
6. Victim accepts the offer expecting 2 XCH.
7. Victim receives **1 XCH**; attacker receives **1 XCH** as royalty.

The victim loses 1 XCH relative to what the GUI told them they would receive. The attacker, as the NFT creator, captures the royalty that the GUI's display concealed. [7](#0-6) [4](#0-3)

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

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L271-272)
```typescript
  const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;

```
