### Title
`calculateNFTRoyalties()` Returns Incorrect `nftSellerNetAmount`, Causing NFT Offer Viewer to Display Inflated "Net Proceeds" - (`packages/gui/src/components/offers/utils.ts`)

### Summary

`calculateNFTRoyalties()` in `utils.ts` assigns `nftSellerNetAmount = amount` (the full offered price) instead of `amount - royaltyAmount` (the actual proceeds after creator fees). The correct formula is present but commented out. The `NFTOfferViewer` renders this value under the label **"Net Proceeds"** with a tooltip explicitly stating it should reflect the asking price *minus* creator fees. An NFT seller viewing a `TokenForNFT` offer therefore sees an inflated figure and may accept an offer expecting to receive more than they actually will.

### Finding Description

In `packages/gui/src/components/offers/utils.ts`, `calculateNFTRoyalties()` computes royalty-related display values:

```typescript
const nftSellerNetAmount: number = amount;          // BUG: should be amount - royaltyAmount
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

The correct subtraction (`amount - royaltyAmount`) is commented out, leaving `nftSellerNetAmount` equal to the gross offered amount regardless of the royalty percentage.

`NFTOfferViewer.tsx` renders this value as **"Net Proceeds"** exclusively in the `TokenForNFT` branch (buyer offers fungible tokens to purchase the NFT from the current owner). The tooltip at that render site reads: *"The net proceeds include the asking price, minus any associated creator fees."* [2](#0-1) 

For a `TokenForNFT` offer of 1 XCH on an NFT with a 10 % royalty:
- `royaltyAmount` = 0.1 XCH (correctly computed)
- `nftSellerNetAmount` = **1 XCH** (shown to seller — incorrect)
- Actual on-chain proceeds to seller = **0.9 XCH**

The same function is called in `NFTOfferEditor.tsx` when the offer creator previews royalty breakdowns, so the inflated figure also appears during offer creation. [3](#0-2) 

### Impact Explanation

An NFT seller viewing or accepting a `TokenForNFT` offer is shown a "Net Proceeds" figure that equals the buyer's full offered amount, not the amount the seller will actually receive after creator royalties are deducted. The seller approves the offer based on a materially incorrect amount. The discrepancy scales with the royalty percentage and the offer size — a 10 % royalty on a 10 XCH offer means the seller expects 10 XCH but receives 9 XCH. This is a direct, concrete asset-accounting error in the offer-acceptance confirmation flow.

**Impact category:** High — the offer viewer displays the wrong amount for a key financial field ("Net Proceeds"), causing a user to approve an offer under false pretenses about the asset amount they will receive.

### Likelihood Explanation

Any NFT with a non-zero `royaltyPercentage` triggers the bug. NFT royalties are a standard, widely-used feature. The `TokenForNFT` offer flow (someone offering XCH/CAT to buy an NFT) is a common trade direction. No special attacker capability is required; the bug is triggered simply by viewing any such offer in the GUI.

### Recommendation

Restore the correct net-proceeds calculation in `calculateNFTRoyalties()`:

```typescript
// Before (buggy):
const nftSellerNetAmount: number = amount;

// After (correct for TokenForNFT — royalty is deducted from the offered amount):
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString)).toFixed(12),
);
``` [4](#0-3) 

If the `makerFee` deduction is also intended (as the original commented-out code suggests), verify whether the maker fee is also paid from the seller's proceeds before including it. At minimum, `royaltyAmount` must be subtracted so the displayed "Net Proceeds" matches what the seller actually receives on-chain.

### Proof of Concept

1. Mint an NFT with `royalty_percentage = 1000` (10 %).
2. Transfer the NFT to a second wallet (so the current owner ≠ creator).
3. From a third wallet, create a `TokenForNFT` offer: offer 1 XCH for the NFT.
4. Import the offer file into the second wallet (the NFT owner).
5. In the offer viewer, observe:
   - **Creator Fee (10%):** 0.1 XCH ✓ (correctly computed)
   - **Net Proceeds:** 1 XCH ✗ (should be 0.9 XCH)
6. The seller accepts the offer expecting 1 XCH; the wallet daemon correctly pays 0.9 XCH to the seller and 0.1 XCH to the creator — a 0.1 XCH shortfall relative to what the GUI promised.

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

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L191-199)
```typescript
      ...calculateNFTRoyalties(
        parseFloat(amount || '0'),
        parseFloat(includedMakerFee || '0'),
        convertRoyaltyToPercentage(nft.royaltyPercentage),
        tab,
      ),
      royaltyPercentage,
    };
  }, [amount, makerFee, nft, tokenWalletInfo, tab]);
```
