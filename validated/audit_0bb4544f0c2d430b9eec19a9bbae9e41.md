The code is confirmed. Let me trace the full impact precisely.

**Code facts:**

In `utils.ts` line 314, `nftSellerNetAmount` is hardcoded to `amount`: [1](#0-0) 

The subtraction `amount - royaltyAmount - makerFee` is commented out. `royaltyAmount` is correctly computed on line 312 but never subtracted.

In `NFTOfferViewer.tsx`, the "Net Proceeds" label is only rendered when `exchangeType === NFTOfferExchangeType.TokenForNFT`: [2](#0-1) 

The tooltip at line 588-591 explicitly promises "the asking price, **minus** any associated creator fees" — but the value rendered at line 596 is `nftSaleInfo?.nftSellerNetAmount`, which equals the full `amount` (not minus royalties).

`overrideNFTSellerAmount` (lines 397-402) also uses `nftSellerNetAmount`, converting it back to mojos and passing it to the "You will receive" summary row — again showing the full amount, not the post-royalty amount: [3](#0-2) 

**Attack path:**

1. Attacker mints an NFT with a high `royaltyPercentage` (e.g., 5000 = 50%) — a legitimate on-chain operation.
2. Attacker (or anyone) creates a `TokenForNFT` offer: maker offers XCH, requests the NFT.
3. Victim (NFT seller/taker) opens the offer in `NFTOfferViewer`. The UI fetches `nft.royaltyPercentage` from the chain via `useNFT(launcherId)` at line 366.
4. `calculateNFTRoyalties(10, fee, 50, TokenForNFT)` returns `nftSellerNetAmount = 10` (not 5).
5. The "Net Proceeds" section displays **10 XCH** with the tooltip "minus any associated creator fees" — but on-chain the seller receives **5 XCH** (royalties deducted from the offered price per the `TokenForNFT` tooltip at line 562-568).
6. Victim accepts, receives 5 XCH instead of the displayed 10 XCH.

**Why the royalty info shown separately doesn't save the user:**

The Creator Fee amount (5 XCH) and percentage (50%) are displayed above the "Net Proceeds" line. However, the "Net Proceeds" label with its explicit tooltip is the authoritative summary figure a user relies on to confirm the deal. Its value contradicts the correct arithmetic visible in the breakdown, creating a UI that a reasonable user would trust over manual recalculation.

**Scope check:**

- Attacker entry point: crafted NFT offer file/import (external file/QR/import payload).
- `royaltyPercentage` comes from on-chain NFT data, not the offer file — but the attacker controls the NFT mint.
- Impact: NFT seller approves an offer displaying wrong net amount → direct XCH loss on acceptance.
- Matches: "Unsafe handling of external... embedded content that produces direct asset loss" and "causes a user to approve... the wrong... amount."

---

### Title
Commented-out royalty subtraction causes `calculateNFTRoyalties` to display inflated "Net Proceeds" to NFT sellers — (`packages/gui/src/components/offers/utils.ts`)

### Summary
`nftSellerNetAmount` in `calculateNFTRoyalties` is hardcoded to the full offer `amount` because the royalty subtraction is commented out. The "Net Proceeds" figure shown to an NFT seller in `NFTOfferViewer` therefore equals the gross offer price, not the actual post-royalty proceeds, misleading the seller into accepting an offer expecting more XCH than they will receive.

### Finding Description
In `calculateNFTRoyalties` (`utils.ts` lines 314–317), the intended computation `amount - royaltyAmount - makerFee` is commented out and replaced with `const nftSellerNetAmount: number = amount`. The `royaltyAmount` is correctly computed on line 312 but never subtracted. `NFTOfferViewer.tsx` renders this value as "Net Proceeds" (line 596) with a tooltip explicitly stating it is "the asking price, minus any associated creator fees" — a promise the code does not fulfill. The same incorrect value is also used as `overrideNFTSellerAmount` (lines 397–402) in the offer summary row.

### Impact Explanation
An NFT seller (taker in a `TokenForNFT` offer) sees "Net Proceeds = X XCH" but on-chain receives `X * (1 - royaltyPct/100)` XCH. For a 50% royalty NFT and a 10 XCH offer, the UI shows 10 XCH net proceeds while the seller receives 5 XCH. This is a direct, quantifiable financial loss triggered by accepting the offer.

### Likelihood Explanation
Any NFT with non-zero royalties triggers this bug. An attacker can mint an NFT with a high royalty percentage and create or distribute offers for it. The victim need only open the offer file in the GUI and trust the "Net Proceeds" label.

### Recommendation
Uncomment and restore the royalty subtraction:
```typescript
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
```
Add a unit test asserting `calculateNFTRoyalties(10, 0, 50, NFTOfferExchangeType.TokenForNFT).nftSellerNetAmount === 5`.

### Proof of Concept
```typescript
// Unit test
const result = calculateNFTRoyalties(10, 0, 50, NFTOfferExchangeType.TokenForNFT);
assert(result.royaltyAmount === 5);       // passes — royalty computed correctly
assert(result.nftSellerNetAmount === 5);  // FAILS — returns 10 (the bug)
```
On-chain, the seller receives 5 XCH; the UI displays 10 XCH as "Net Proceeds."

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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L397-402)
```typescript
  const overrideNFTSellerAmount =
    exchangeType === NFTOfferExchangeType.TokenForNFT
      ? assetType === OfferAsset.CHIA
        ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
        : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : undefined;
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L580-599)
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
                  )}
```
