### Title
Commented-Out Netting Logic in `calculateNFTRoyalties` Causes Inflated "Net Proceeds" Display, Inducing NFT Sellers to Accept Under-Valued Offers - (File: `packages/gui/src/components/offers/utils.ts`)

---

### Summary

`calculateNFTRoyalties` in `packages/gui/src/components/offers/utils.ts` sets `nftSellerNetAmount` to the raw offer `amount` instead of netting out the royalty and maker fee. The correct subtraction is present but permanently commented out. As a result, the `NFTOfferViewer` displays an inflated "Net Proceeds" figure to the NFT seller at the moment they decide whether to accept an incoming offer, causing them to believe they will receive more XCH/CAT than the transaction will actually deliver.

---

### Finding Description

`calculateNFTRoyalties` is the sole function that computes what the NFT seller will net after royalties and fees are deducted. Its return value `nftSellerNetAmount` is consumed directly by `NFTOfferViewer` to populate both the "Net Proceeds" label and the `overrideNFTSellerAmount` value shown in the offer summary row.

The implementation contains the correct formula, but it is permanently commented out:

```typescript
// packages/gui/src/components/offers/utils.ts  L314-L317
const nftSellerNetAmount: number = amount;
// : parseFloat(
//     (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
//   );
``` [1](#0-0) 

Because the comment-out is unconditional, `nftSellerNetAmount` is always equal to the full offer `amount`, regardless of the NFT's royalty percentage or the maker fee.

`NFTOfferViewer` then uses this value in two ways:

**1. "Net Proceeds" label** — shown only in the `TokenForNFT` exchange type (buyer offering XCH/CAT for an NFT), i.e., exactly the scenario where the NFT seller is the accepting party:

```typescript
// NFTOfferViewer.tsx  L595-L597
<FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} /> {displayName}
``` [2](#0-1) 

**2. `overrideNFTSellerAmount`** — passed into the offer summary row to override the token amount displayed under "You will receive":

```typescript
// NFTOfferViewer.tsx  L397-L402
const overrideNFTSellerAmount =
  exchangeType === NFTOfferExchangeType.TokenForNFT
    ? assetType === OfferAsset.CHIA
      ? chiaToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
      : catToMojo(nftSaleInfo?.nftSellerNetAmount ?? 0)
    : undefined;
``` [3](#0-2) 

Both values are derived from the same broken `nftSellerNetAmount = amount`, so every royalty-bearing NFT offer shows the seller the full pre-royalty amount as their net proceeds.

A secondary consequence appears in `NFTOfferEditor`, where the negative-amount safety warning is gated on `nftSellerNetAmount < 0`. Because `nftSellerNetAmount` is always the raw positive `amount`, the warning is permanently suppressed even when royalties would make the real net proceeds negative:

```typescript
// NFTOfferEditor.tsx  L271
const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
``` [4](#0-3) 

---

### Impact Explanation

When a buyer creates a `TokenForNFT` offer for an NFT that carries a royalty (e.g., 10 %), the NFT seller opens the offer in `NFTOfferViewer` and sees:

- **"Net Proceeds": 10 XCH** (the full offer amount — incorrect)
- **"You will receive": 10 XCH** (via `overrideNFTSellerAmount` — incorrect)
- **"Creator Fee (10%)": 1 XCH** (correctly computed)

The seller reads these figures and concludes they will net 10 XCH. They accept. The on-chain transaction correctly routes 1 XCH to the creator and delivers only **9 XCH** to the seller. The seller has approved a transaction for the wrong amount — a direct, concrete asset loss relative to their informed expectation at the moment of signing.

This matches the allowed High impact: *"Corruption, spoofing, or unsafe trust of… offer… state that causes a user to approve… the wrong… amount."*

---

### Likelihood Explanation

- Any NFT with a non-zero `royaltyPercentage` triggers the bug; royalties are a standard feature of Chia NFTs.
- The `TokenForNFT` flow (buyer creates offer, seller accepts) is a primary use case of the offer system.
- No special attacker capability is required; the bug is triggered by the normal offer-viewing flow for any royalty-bearing NFT.
- The discrepancy between displayed and actual proceeds grows linearly with royalty percentage, making high-royalty NFTs (≥ 20 %, which the UI itself flags as common enough to warn about) particularly impactful.

---

### Recommendation

Uncomment and restore the correct netting formula:

```typescript
// packages/gui/src/components/offers/utils.ts
const nftSellerNetAmount: number = parseFloat(
  (amount - parseFloat(royaltyAmountString) - makerFee).toFixed(12),
);
```

Ensure the result is clamped to zero (or surfaced as a warning) when royalties plus fees exceed the offer amount, so the `showNegativeAmountWarning` guard in `NFTOfferEditor` also functions correctly.

---

### Proof of Concept

**Setup:** Create a Chia NFT with `royalty_percentage = 1000` (10 %). Have a buyer create a `TokenForNFT` offer for 10 XCH.

**Steps:**
1. The NFT seller opens the offer in `NFTOfferViewer` (old offers UI).
2. Observe the "Net Proceeds" label and the "You will receive" summary row — both display **10 XCH**.
3. The seller accepts the offer.
4. After confirmation, the seller's wallet balance increases by **9 XCH** (10 XCH minus 1 XCH royalty paid to the creator).

**Root cause trace:**

```
calculateNFTRoyalties(10, 0, 10, NFTOfferExchangeType.TokenForNFT)
  → royaltyAmount      = 1
  → nftSellerNetAmount = 10   ← should be 9
  → totalAmount        = 10

NFTOfferViewer:
  nftSaleInfo.nftSellerNetAmount = 10
  overrideNFTSellerAmount        = chiaToMojo(10)   ← shown as "You will receive"
  "Net Proceeds" label           = 10 XCH           ← shown to seller before accept
```

The seller approves a transaction believing they receive 10 XCH; they receive 9 XCH. The 1 XCH difference is a direct, irreversible asset loss caused by the incorrect display at the moment of offer acceptance.

### Citations

**File:** packages/gui/src/components/offers/utils.ts (L314-317)
```typescript
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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L594-598)
```typescript
                      </Flex>
                      <Typography variant="h5" fontWeight="bold">
                        <FormatLargeNumber value={new BigNumber(nftSaleInfo?.nftSellerNetAmount ?? 0)} /> {displayName}
                      </Typography>
                    </Flex>
```

**File:** packages/gui/src/components/offers/NFTOfferEditor.tsx (L271-271)
```typescript
  const showNegativeAmountWarning = (nftSellerNetAmount ?? 0) < 0;
```
