### Title
Invalid 1:1 NFT-to-fungible-asset assumption in `NFTOfferDetails` causes wrong token amount display on multi-asset NFT offers, enabling approval of under-disclosed spend - (File: packages/gui/src/components/offers/NFTOfferViewer.tsx)

---

### Summary
`NFTOfferDetails` silently assumes every NFT offer involves exactly one fungible asset. When a multi-asset NFT offer (e.g., NFT for 10 XCH + 1000 CAT) is opened in the viewer, the royalty-adjusted amount computed from only the **first** matching asset is applied as `overrideNFTSellerAmount` to **every** fungible token row. A victim who opens an attacker-crafted offer sees a drastically understated amount for secondary assets and may accept a transaction that spends far more than displayed.

---

### Finding Description

In `NFTOfferDetails`, `getNFTPriceWithoutRoyalties(summary)` iterates `[OfferAsset.TOKEN, OfferAsset.CHIA]` and returns the **first** matching asset only: [1](#0-0) 

The returned `amount` and `assetType` are used to compute `overrideNFTSellerAmount`: [2](#0-1) 

This single value is then passed to **both** `NFTOfferSummaryRow` components (offered and requested sides): [3](#0-2) 

Inside `NFTOfferSummaryRow`, the override is forwarded to **every** `OfferSummaryTokenRow` regardless of which asset it represents: [4](#0-3) 

And in `OfferSummaryTokenRow`, the override unconditionally replaces the actual on-chain amount: [5](#0-4) 

The codebase itself acknowledges the assumption in the sibling function `summaryStringsForNFTOffer`: [6](#0-5) 

That comment only covers filename generation, but the same broken assumption is silently embedded in the security-critical offer acceptance viewer with no guard.

`NFTOfferViewer` (which wraps `NFTOfferDetails`) is imported and used in `OfferManager.tsx` for both stored and imported offers, and the `imported` prop enables the live "Accept Offer" button: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**Concrete scenario — NFT for 10 XCH + 1000 CAT, NFT has 5% royalty:**

| Step | Value |
|---|---|
| `getNFTPriceWithoutRoyalties` returns | TOKEN (CAT), `amount` = 1000 |
| `nftSaleInfo.nftSellerNetAmount` | 1000 (CAT) |
| `overrideNFTSellerAmount` | `catToMojo(1000)` = 1,000,000 mojos |
| XCH row displayed amount | `mojoToChiaLocaleString(1,000,000)` = **0.000001 XCH** |
| Actual XCH spend | **10 XCH** |

The victim's confirmation dialog reads "In exchange for: 0.000001 XCH + 1000 CAT." They approve. The actual transaction — determined by the raw offer blob passed to `takeOffer` — spends 10 XCH + 1000 CAT. The display understates the XCH cost by a factor of 10,000,000×.

This matches the **High** impact class: "Corruption or spoofing of offer state that causes a user to approve the wrong amount."

---

### Likelihood Explanation

- The Chia protocol natively supports multi-asset offers; an attacker can craft one with the CLI (`chia wallet make_offer`) without any special privilege.
- The victim only needs to open a shared `.offer` file — a normal user workflow.
- The attack requires the NFT to have a non-zero `royaltyPercentage` (otherwise `nftSaleInfo` is `undefined` and `nftSaleInfo?.nftSellerNetAmount ?? 0` = 0, making `overrideNFTSellerAmount` = 0, which shows **zero** for all token rows — an equally wrong but more obviously broken display).
- No leaked keys, host compromise, or cryptographic break is required.

---

### Recommendation

1. **Make `overrideNFTSellerAmount` asset-specific.** Key it by `assetId` so each `OfferSummaryTokenRow` only receives the override for its own asset, not a global scalar.
2. **Guard the override on `nftSaleInfo` being defined.** Currently `overrideNFTSellerAmount` is set to `catToMojo(0)` or `chiaToMojo(0)` even when there are no royalties, which also corrupts the display.
3. **Reject or warn on multi-fungible-asset NFT offers** in `NFTOfferDetails` until the display logic is corrected, consistent with the existing `// TODO: Remove 1:1 NFT <--> XCH assumption` note.

---

### Proof of Concept

```bash
# Attacker: craft a multi-asset NFT offer (NFT for 10 XCH + 1000 CAT)
chia wallet make_offer \
  --offer <nft_launcher_id>:1 \
  --request xch:10 \
  --request <cat_asset_id>:1000 \
  --output attacker.offer
# Share attacker.offer with victim (e.g., via marketplace link or direct message)
```

Victim opens `attacker.offer` in Chia GUI → Offers → View Offer File:

1. `NFTOfferDetails` renders via `NFTOfferViewer`.
2. `getNFTPriceWithoutRoyalties` returns the CAT entry (TOKEN checked first); `amount` = 1000 CAT.
3. `overrideNFTSellerAmount` = `catToMojo(1000)` = 1,000,000 mojos.
4. The XCH row in `OfferSummaryTokenRow` displays `mojoToChiaLocaleString(1,000,000)` = **0.000001 XCH**.
5. Victim reads "In exchange for: 0.000001 XCH + 1000 CAT" and clicks **Accept Offer**.
6. `takeOffer({ offer: offerData, fee })` executes with the original offer blob — actual spend: **10 XCH + 1000 CAT**.

### Citations

**File:** packages/gui/src/components/offers/utils.ts (L43-46)
```typescript
  // const makerAssetType = offerAssetTypeForAssetId
  // TODO: Remove 1:1 NFT <--> XCH assumption
  const makerEntry: [string, string] = Object.entries(summary.offered)[0] as [string, string];
  const takerEntry: [string, string] = Object.entries(summary.requested)[0] as [string, string];
```

**File:** packages/gui/src/components/offers/utils.ts (L279-293)
```typescript
export function getNFTPriceWithoutRoyalties(
  summary: OfferSummaryRecord,
): GetNFTPriceWithoutRoyaltiesResult | undefined {
  for (const assetType of [OfferAsset.TOKEN, OfferAsset.CHIA]) {
    const assetId = offerAssetIdForAssetType(assetType, summary);
    if (assetId) {
      const amountInMojos = offerAssetAmountForAssetId(assetId, summary);
      if (amountInMojos) {
        const amountInTokens = assetType === OfferAsset.CHIA ? mojoToChia(amountInMojos) : mojoToCAT(amountInMojos);
        return { amount: amountInTokens.toNumber(), assetId, assetType };
      }
    }
  }

  return undefined;
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L118-132)
```typescript
  const rows: (React.ReactElement | null)[] = assetIdsToTypes.map((entry) => {
    const [assetId, assetType]: [string, OfferAsset | undefined] = Object.entries(entry)[0];

    switch (assetType) {
      case undefined:
        return null;
      case OfferAsset.CHIA: // fall-through
      case OfferAsset.TOKEN:
        return (
          <OfferSummaryTokenRow
            assetId={assetId}
            amount={summaryData[assetId]}
            overrideNFTSellerAmount={overrideNFTSellerAmount}
          />
        );
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L283-303)
```typescript
  const makerSummary: React.ReactElement = (
    <NFTOfferSummaryRow
      title={makerTitle}
      summaryKey="offered"
      summary={summary}
      unknownAssets={isMyOffer ? undefined : takerUnknownAssets}
      rowIndentation={rowIndentation}
      showNFTPreview={showNFTPreview}
      overrideNFTSellerAmount={overrideNFTSellerAmount}
    />
  );
  const takerSummary: React.ReactElement = (
    <NFTOfferSummaryRow
      title={takerTitle}
      summaryKey="requested"
      summary={summary}
      unknownAssets={isMyOffer ? undefined : makerUnknownAssets}
      rowIndentation={rowIndentation}
      showNFTPreview={showNFTPreview}
      overrideNFTSellerAmount={overrideNFTSellerAmount}
    />
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

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L623-644)
```typescript
              {imported && (
                <Flex
                  flexDirection="column"
                  flexGrow={1}
                  alignItems="flex-end"
                  justifyContent="flex-end"
                  style={{ paddingBottom: '1em' }}
                >
                  <Flex justifyContent="flex-end" gap={2}>
                    <Button variant="outlined" onClick={() => navigate(-1)} disabled={isAccepting}>
                      <Trans>Back</Trans>
                    </Button>
                    <ButtonLoading
                      variant="contained"
                      color="primary"
                      type="submit"
                      disabled={!isValid || isMissingRequestedAsset || isLoading}
                      loading={isAccepting}
                    >
                      <Trans>Accept Offer</Trans>
                    </ButtonLoading>
                  </Flex>
```

**File:** packages/gui/src/components/offers/OfferSummaryRow.tsx (L143-149)
```typescript
  const { assetId, amount: originalAmount, rowNumber, overrideNFTSellerAmount } = props;
  const { lookupByAssetId } = useAssetIdName();
  const assetIdInfo = lookupByAssetId(assetId);
  const amount = overrideNFTSellerAmount ?? originalAmount;
  const displayAmount = assetIdInfo
    ? formatAmountForWalletType(amount as number, assetIdInfo.walletType)
    : mojoToCATLocaleString(amount);
```

**File:** packages/gui/src/components/offers/OfferManager.tsx (L42-42)
```typescript
import NFTOfferViewer from './NFTOfferViewer';
```
