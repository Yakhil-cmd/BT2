### Title
NFT Offer "Net Proceeds" Displays Inflated Amount Due to Commented-Out Royalty Deduction - (File: packages/gui/src/components/offers/utils.ts)

### Summary
`calculateNFTRoyalties()` in `utils.ts` hardcodes `nftSellerNetAmount` to the full asking `amount` instead of `amount - royaltyAmount`. The correct deduction was explicitly commented out. This causes the NFT offer editor and viewer to display an inflated "Net Proceeds" / "You will receive" figure to the NFT seller, misrepresenting what they will actually receive after royalties are deducted on-chain.

### Finding Description
In `packages/gui/src/components/offers/utils.ts`, the `calculateNFTRoyalties()` function computes `nftSellerNetAmount` as:

```ts
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
```

The correct calculation (`amount - royaltyAmount`) was commented out, leaving `nftSellerNetAmount` equal to the full asking price regardless of the NFT's `royaltyPercentage`.

This value propagates to two user-facing surfaces:

1. **NFT Offer Editor** (`NFTOfferEditor.tsx`, line 365): When the NFT seller is creating a "Sell an NFT" offer, the label "You will receive" renders `nftSellerNetAmount` — showing the full price, not price minus royalties.

2. **NFT Offer Viewer** (`NFTOfferViewer.tsx`, lines 595–597): The "Net Proceeds" field — explicitly described in its tooltip as "the asking price, minus any associated creator fees" — renders `nftSaleInfo?.nftSellerNetAmount`, which is the full price. Additionally, `overrideNFTSellerAmount` (lines 397–402) is derived from this same inflated value and is passed into `NFTOfferSummary` to override the displayed token amount in the purchase summary.

### Impact Explanation
An NFT seller creating or reviewing an offer sees "Net Proceeds: X XCH" but will actually receive `X × (1 - royaltyPercentage/100)` XCH after the on-chain royalty transfer. For an NFT with a 10% royalty and a 10 XCH asking price, the GUI displays "Net Proceeds: 10 XCH" while the seller actually receives 9 XCH. The seller approves the offer based on a materially wrong amount. This fits the allowed High impact: "display the wrong... amount... that causes a user to approve... the wrong... amount."

### Likelihood Explanation
Any NFT with `royaltyPercentage > 0` triggers the discrepancy. The Chia NFT standard supports royalties up to 100%, and many NFT collections use royalties of 2–10%. The bug is always active for such NFTs; no special attacker action is required. The seller simply creates or views an offer through the standard GUI flow.

### Recommendation
Restore the commented-out deduction in `calculateNFTRoyalties()`:

```ts
// packages/gui/src/components/offers/utils.ts
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString)).toFixed(12),
);
```

The `makerFee` deduction in the original commented code should be evaluated separately — the maker fee is paid by the seller on top of the royalty, so whether to include it in "Net Proceeds" depends on the exchange direction. At minimum, `royaltyAmount` must be subtracted so the displayed figure matches what the seller actually receives.

### Proof of Concept
1. An NFT has `royaltyPercentage = 1000` (10%).
2. The seller opens the NFT Offer Editor and enters a token amount of `10 XCH`.
3. `calculateNFTRoyalties(10, 0, 10, NFTOfferExchangeType.NFTForToken)` is called.
4. `royaltyAmount = 1 XCH`; `nftSellerNetAmount = 10` (should be `9`).
5. The GUI renders "You will receive: 10 XCH" and "Creator Fee (10%): 1 XCH".
6. The seller creates the offer believing they will net 10 XCH.
7. On-chain, 1 XCH is transferred to the royalty address; the seller receives 9 XCH.
8. The seller has received 1 XCH less than the GUI indicated, with no warning.

---

**Affected code locations:**

`calculateNFTRoyalties` hardcodes `nftSellerNetAmount = amount`: [1](#0-0) 

`NFTOfferEditor` renders "You will receive" using `nftSellerNetAmount`: [2](#0-1) 

`NFTOfferViewer` renders "Net Proceeds" using `nftSaleInfo?.nftSellerNetAmount`: [3](#0-2) 

`overrideNFTSellerAmount` derived from the inflated value and passed to the purchase summary: [4](#0-3)

### Citations

**File:** packages/gui/src/components/offers/utils.ts (L314-317)
```typescript
  const nftSellerNetAmount: number = amount;
  // : parseFloat(
  //     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
  //   );
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L358-366)
```typescript
                    {tab === NFTOfferExchangeType.NFTForToken ? (
                      <Trans>You will receive</Trans>
                    ) : (
                      <Trans>They will receive</Trans>
                    )}
                  </Typography>
                  <Typography variant="subtitle1" color={showNegativeAmountWarning ? StateColor.ERROR : 'inherit'}>
                    <FormatLargeNumber value={new BigNumber(nftSellerNetAmount ?? 0)} />{' '}
                    {tokenWalletInfo.symbol ?? tokenWalletInfo.name ?? ''}
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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L583-597)
```typescript
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
