### Title
NFT Offer Net Proceeds Permanently Hardcoded to Full Amount, Bypassing Royalty Deduction and Negative-Amount Guard - (File: packages/gui/src/components/offers/utils.ts)

### Summary

In `calculateNFTRoyalties`, the `nftSellerNetAmount` field is unconditionally set to the raw `amount` input instead of `amount - royaltyAmount - makerFee`. The correct formula is present but commented out. Every downstream consumer that displays "You will receive" or "Net Proceeds" to the user therefore shows the full asking price, not the actual post-royalty proceeds. The safety guard `showNegativeAmountWarning` is also permanently dead because `nftSellerNetAmount` can never be negative when it equals `amount`.

### Finding Description

`calculateNFTRoyalties` in `packages/gui/src/components/offers/utils.ts` computes royalty amounts correctly but then assigns the wrong value to `nftSellerNetAmount`:

```typescript
// packages/gui/src/components/offers/utils.ts  lines 312-317
const royaltyAmount: number = royaltyPercentage ? (royaltyPercentage / 100) * amount : 0;
const royaltyAmountString: string = formatAmount(royaltyAmount);
const nftSellerNetAmount: number = amount;          // ← always the full price
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );                                              // ← correct formula, commented out
``` [1](#0-0) 

This broken value propagates to two reachable UI surfaces:

**1. NFT Offer Editor (`NFTOfferEditor.tsx`) — offer creation**

`NFTOfferConditionalsPanel` calls `calculateNFTRoyalties` and renders `nftSellerNetAmount` as "You will receive" (NFTForToken tab) or "They will receive" (TokenForNFT tab):

```typescript
// NFTOfferEditor.tsx  line 271
const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
// line 365
<FormatLargeNumber value={new BigNumber(nftSellerNetAmount ?? 0)} />
``` [2](#0-1) [3](#0-2) 

Because `nftSellerNetAmount === amount` (always positive), `showNegativeAmountWarning` is permanently `false` and the error message "Unable to create an offer where the net amount is negative" can never appear.

**2. NFT Offer Viewer (`NFTOfferViewer.tsx`) — offer acceptance**

`NFTOfferDetails` calls the same function and uses `nftSellerNetAmount` in two ways:

- As `overrideNFTSellerAmount` passed to `NFTOfferSummary` (the primary "You will receive" display in the acceptance dialog):

```typescript
// NFTOfferViewer.tsx  lines 397-402
const overrideNFTSellerAmount =
  exchangeType === NFTOfferExchangeType.TokenForNFT
    ? assetType === OfferAsset.CHIA
      ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
    : undefined;
``` [4](#0-3) 

- Directly as the "Net Proceeds" figure:

```typescript
// NFTOfferViewer.tsx  line 596
<FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} />
``` [5](#0-4) 

Both surfaces display the full asking price instead of `amount - royaltyAmount`.

Both `CreateNFTOfferEditor` and `NFTOfferViewer` are imported and rendered by `OfferManager.tsx`, confirming the code paths are live and reachable by any user. [6](#0-5) 

### Impact Explanation

An NFT seller creating or reviewing an offer for an NFT with royalties enabled sees an inflated "You will receive" / "Net Proceeds" figure equal to the full asking price. The actual on-chain settlement deducts the royalty from that amount. For example, with a 20% royalty on a 1 XCH offer, the UI displays "You will receive: 1 XCH" while the seller actually receives 0.8 XCH. The negative-amount guard being permanently disabled means no warning is shown even in extreme cases (e.g., 99% royalty). This constitutes offer-state spoofing that causes a user to approve the wrong amount — a High-severity impact under the allowed scope.

### Likelihood Explanation

Any NFT with a non-zero `royaltyPercentage` triggers the bug. NFT royalties are a standard, widely-used feature in the Chia ecosystem. The attacker path requires no special privileges: a malicious NFT creator sets a high royalty percentage, lists the NFT for sale or shares an offer file, and the victim's GUI displays the full asking price as their net proceeds. The victim accepts, and the royalty is silently extracted on-chain.

### Recommendation

Uncomment and restore the correct formula for `nftSellerNetAmount` in `calculateNFTRoyalties`:

```typescript
// packages/gui/src/components/offers/utils.ts
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
``` [7](#0-6) 

This restores the intended behavior: the displayed net proceeds correctly reflect the amount after royalty and fee deductions, and `showNegativeAmountWarning` becomes functional again.

### Proof of Concept

1. Mint an NFT with `royalty_percentage = 2000` (20%).
2. Open the Chia GUI and navigate to **Offers → Create an NFT Offer → Sell an NFT**.
3. Enter the NFT identifier and set the asking price to **1 XCH**.
4. Observe: the UI displays **"You will receive: 1 XCH"** — the royalty deduction of 0.2 XCH is absent.
5. `showNegativeAmountWarning` remains `false` regardless of royalty percentage.
6. Alternatively, share the offer file with a counterparty. They open it in the viewer; the **"Net Proceeds"** line shows **1 XCH** instead of **0.8 XCH**, and `overrideNFTSellerAmount` passed to the acceptance summary is computed from the inflated value.
7. Root cause: `nftSellerNetAmount = amount` at line 314 of `utils.ts` instead of `amount - royaltyAmount - makerFee`.

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

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L271-271)
```typescript
  const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L364-366)
```typescript
                  <Typography variant="subtitle1" color={showNegativeAmountWarning ? StateColor.ERROR : 'inherit'}>
                    <FormatLargeNumber value={new BigNumber(nftSellerNetAmount ?? 0)} />{' '}
                    {tokenWalletInfo.symbol ?? tokenWalletInfo.name ?? ''}
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L714-731)
```typescript
export function CreateNFTOfferEditor(props: CreateNFTOfferEditorProps) {
  const { nft, exchangeType = NFTOfferExchangeType.TokenForNFT, referrerPath, onOfferCreated } = props;

  const title = <Trans>Create an NFT Offer</Trans>;
  const navElement = referrerPath ? (
    <Back variant="h5" to={referrerPath}>
      {title}
    </Back>
  ) : (
    <>{title}</>
  );

  return (
    <Grid container>
      <Flex flexDirection="column" flexGrow={1} gap={3}>
        <Flex>{navElement}</Flex>
        <NFTOfferEditor nft={nft} onOfferCreated={onOfferCreated} exchangeType={exchangeType} />
      </Flex>
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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L595-597)
```typescript
                      <Typography variant="h5" fontWeight="bold">
                        <FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} /> {displayName}
                      </Typography>
```
