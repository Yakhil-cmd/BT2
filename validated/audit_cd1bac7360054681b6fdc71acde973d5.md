### Title
NFT Seller Net Proceeds Hardcoded to Full Price, Omitting Royalty Deduction in Offer Review - (File: packages/gui/src/components/offers/utils.ts)

### Summary
In `calculateNFTRoyalties`, the `nftSellerNetAmount` field is hardcoded to the full offer `amount` instead of the correct value of `amount - royaltyAmount - makerFee`. The correct calculation is commented out directly in the source. This causes the "You will receive" / "Net Proceeds" display shown to an NFT seller during offer creation and offer acceptance review to be inflated by the full royalty amount, causing the seller to approve an offer under a false understanding of their actual proceeds.

### Finding Description

In `packages/gui/src/components/offers/utils.ts`, the `calculateNFTRoyalties` function computes display values for the NFT offer UI:

```typescript
export function calculateNFTRoyalties(
  amount: number,
  makerFee: number,
  royaltyPercentage: number,
  exchangeType: NFTOfferExchangeType,
): CalculateNFTRoyaltiesResult {
  const royaltyAmount: number = royaltyPercentage ? (royaltyPercentage / 100) * amount : 0;
  const royaltyAmountString: string = formatAmount(royaltyAmount);
  const nftSellerNetAmount: number = amount;   // <-- BUG: always equals full price
  // : parseFloat(
  //     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
  //   );
``` [1](#0-0) 

The correct formula — `amount - royaltyAmount - makerFee` — is commented out. `nftSellerNetAmount` is unconditionally set to `amount`, the gross price, regardless of royalties.

This value is consumed in two user-facing flows:

**1. Offer creation (`NFTOfferEditor.tsx`):** The "You will receive" label shown to the NFT seller during offer creation uses `nftSellerNetAmount`: [2](#0-1) 

**2. Offer acceptance review (`NFTOfferViewer.tsx`):** `nftSellerNetAmount` is converted to mojos and passed as `overrideNFTSellerAmount` to the offer summary panel, and also rendered directly as "Net Proceeds": [3](#0-2) [4](#0-3) 

The royalty percentage is correctly computed via `convertRoyaltyToPercentage` (divides the on-chain basis-point value by 100): [5](#0-4) 

And the royalty amount itself is correctly calculated on line 312. The bug is exclusively that the net proceeds figure ignores this already-computed deduction.

### Impact Explanation

An NFT seller — either creating an offer or reviewing an imported one — is shown a "You will receive" / "Net Proceeds" figure equal to the **full gross price**, not the price minus royalties. For an NFT with a 10% royalty and a 1 XCH offer, the GUI displays "You will receive: 1 XCH" when the seller will actually receive 0.9 XCH. The seller approves or creates the offer based on this inflated figure. This is a direct accounting spoofing issue in the offer confirmation flow that causes a user to approve an offer displaying the wrong amount — matching the allowed High impact: *"state that causes a user to approve … the wrong … amount."*

### Likelihood Explanation

Any NFT with a non-zero `royaltyPercentage` triggers this bug. NFT royalties are common and the royalty percentage is prominently displayed in the same UI panel, making the discrepancy between the displayed royalty and the (wrong) net proceeds figure internally inconsistent and exploitable by any NFT creator who sets royalties. No special attacker capability is required; the bug fires for every NFT offer involving royalties.

### Recommendation

Uncomment and restore the correct net proceeds calculation in `calculateNFTRoyalties`:

```typescript
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
``` [6](#0-5) 

Additionally, add a unit test asserting that `nftSellerNetAmount` equals `amount - royaltyAmount` for a non-zero royalty percentage to prevent regression.

### Proof of Concept

1. Mint an NFT with `royaltyPercentage = 1000` (10%).
2. Open the NFT Offer Editor and select "Sell an NFT".
3. Enter the NFT ID and set the token amount to 1 XCH.
4. Observe: "You will receive: 1 XCH" — the royalty deduction (0.1 XCH) is absent.
5. The correct display should be "You will receive: 0.9 XCH".
6. The seller creates or accepts the offer believing they will receive 1 XCH; on-chain they receive 0.9 XCH.

The root cause is confirmed at: [7](#0-6)

### Citations

**File:** packages/gui/src/components/offers/utils.ts (L306-317)
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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L397-402)
```typescript
  const overrideNFTSellerAmount =
    exchangeType === NFTOfferExchangeType.TokenForNFT
      ? assetType === OfferAsset.CHIA
        ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
        : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : undefined;
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L593-598)
```typescript
                        </Flex>
                      </Flex>
                      <Typography variant="h5" fontWeight="bold">
                        <FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} /> {displayName}
                      </Typography>
                    </Flex>
```

**File:** packages/gui/src/util/nfts.ts (L23-25)
```typescript
export function convertRoyaltyToPercentage(royalty: number): number {
  return royalty / 100;
}
```
