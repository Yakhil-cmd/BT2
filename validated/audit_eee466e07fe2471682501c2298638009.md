### Title
Attacker-Controlled `royalty_percentage` in Offer `infos` Spoofs `amountWithRoyalties` in WalletConnect Confirmation Dialog — (`packages/gui/src/electron/commands/parseCommandDisplay.ts`)

---

### Summary

When a WalletConnect dApp triggers `chia_wallet.take_offer`, the GUI builds the "Total Amount with Royalties" display value using the `royalty_percentage` embedded in the offer's own `infos` driver dict — data fully controlled by the offer maker. A best-effort override from `nftGetInfo` is the only correction, but it is gated behind a `data_uris` presence check that is unrelated to royalties. If that gate fails (e.g., the NFT has no `data_uris` in the wallet response, or `nftGetInfo` throws), the attacker's royalty value is used verbatim. The user sees a misleading "Total Amount with Royalties" and may approve an offer believing they will spend less XCH than the on-chain NFT puzzle will actually enforce.

---

### Finding Description

`parseCommandDisplay` handles `chia_wallet.take_offer` by calling `getOfferSummary` on the offer string, then extracting royalty percentages from the returned `summary.infos` field via `offerSummaryRoyaltyPercentages`. [1](#0-0) 

`royaltyPercentageForDriverInfo` reads `transfer_program.royalty_percentage` directly from the offer's embedded driver info — data the offer maker (attacker) wrote: [2](#0-1) 

This attacker-supplied value is passed as the initial `royaltyPercentage` argument into `parseWalletDeltaItem` for each NFT item: [3](#0-2) 

The only correction is a best-effort `nftGetInfo` call, but the royalty override is nested inside a `data_uris` truthiness check — a condition that exists to fetch a preview image, not to validate royalties: [4](#0-3) 

`data_uris` is typed as optional (`data_uris?: string[]`) in the response type: [5](#0-4) 

If `data_uris` is absent from the wallet's response, or if `nftGetInfo` throws (silently caught), the attacker's royalty percentage is kept. The NFT item's `royaltyPercentage` then feeds `royaltyPercentagesForSide`, which drives `formatAmountWithRoyalties`: [6](#0-5) 

The resulting `amountWithRoyalties` string is rendered in the WalletConnect confirmation dialog as the authoritative "Total Amount with Royalties": [7](#0-6) 

---

### Impact Explanation

An attacker who crafts an offer with `royalty_percentage: 0` (or omits it) in the driver dict causes the confirmation dialog to display no royalty cost — or a drastically understated one. The user sees only the base XCH amount and approves. Because Chia NFT royalties are enforced by the on-chain NFT puzzle, the actual transaction deducts the correct royalty from the user's wallet regardless of what the GUI showed. The user loses more XCH than the confirmation dialog indicated, with no warning.

---

### Likelihood Explanation

The attack is reachable by any WalletConnect dApp that can send a `take_offer` command with a crafted offer string. The `nftGetInfo` correction fires in the common case (NFT has `data_uris`), but fails silently whenever:
- The wallet returns `nft_info` without a `data_uris` field (valid per the optional type)
- `nftGetInfo` throws for any reason (network hiccup, wallet not synced, unknown coin)
- The NFT is newly minted and not yet indexed

All three are realistic conditions, especially for freshly minted NFTs used in targeted attacks.

---

### Recommendation

Decouple the royalty-percentage override from the `data_uris` gate. The on-chain royalty percentage should always be fetched and applied independently of whether a preview URL is available:

```typescript
try {
  const nftInfo = await nftGetInfo(key);
  if (nftInfo?.success && nftInfo.nft_info) {
    // Royalty override: always apply when available, regardless of data_uris
    if ('royalty_percentage' in nftInfo.nft_info) {
      result.royaltyPercentage = parseRoyaltyPercentage(nftInfo.nft_info.royalty_percentage);
    }
    // Preview URL: separate, best-effort
    if (nftInfo.nft_info.data_uris) {
      const previewUrl = nftInfo.nft_info.data_uris.find((u) => isValidURL(u));
      if (previewUrl) result.previewUrl = previewUrl;
    }
  }
} catch {
  // metadata is best effort
}
```

Additionally, add an upper-bound cap in `parseRoyaltyPercentage` (e.g., reject values above `10000`, i.e., 100%) and consider displaying a warning when the on-chain royalty could not be confirmed, rather than silently falling back to offer-embedded data.

---

### Proof of Concept

1. Attacker mints an NFT with `royalty_percentage = 1000` (10%) on-chain.
2. Attacker creates an offer selling that NFT for 1 XCH, but embeds `royalty_percentage: 0` in the offer's driver dict `infos`.
3. Attacker connects a malicious WalletConnect dApp to the victim's Chia GUI and sends:
   ```json
   { "command": "chia_wallet.take_offer", "params": { "offer": "<crafted_offer_string>" } }
   ```
4. `getOfferSummary` returns `infos[nftId].transfer_program.royalty_percentage = 0`.
5. `offerSummaryRoyaltyPercentages` produces `royaltyPercentage = undefined` for the NFT.
6. `nftGetInfo` returns `nft_info` without `data_uris` (e.g., NFT has no image), so the override block is skipped.
7. `royaltyPercentagesForSide` returns `[]`; `formatAmountWithRoyalties` returns `undefined`.
8. Confirmation dialog shows: **"Spending: 1 XCH"** — no royalty line.
9. Victim approves. On-chain settlement deducts **1.1 XCH** (1 XCH + 10% royalty to attacker's royalty address).
10. Victim loses 0.1 XCH beyond what the confirmation dialog indicated.

### Citations

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L60-81)
```typescript
function royaltyPercentageForDriverInfo(driverInfo: unknown): number | undefined {
  if (!isPlainObject(driverInfo)) {
    return undefined;
  }

  const { also } = driverInfo;
  if (!isPlainObject(also)) {
    return undefined;
  }

  const ownershipLayer = also.also;
  if (!isPlainObject(ownershipLayer)) {
    return undefined;
  }

  const transferProgram = ownershipLayer.transfer_program;
  if (!isPlainObject(transferProgram)) {
    return undefined;
  }

  return parseRoyaltyPercentage(transferProgram.royalty_percentage);
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L184-206)
```typescript
function offerSummaryRoyaltyPercentages(offerSummary: OfferSummaryForDisplay): AssetRoyaltyPercentages {
  const royaltyPercentages: AssetRoyaltyPercentages = {
    spending: {},
    receiving: {},
  };

  const { infos } = offerSummary;
  if (!isPlainObject(infos)) {
    return royaltyPercentages;
  }

  for (const assetId of Object.keys(offerSummary.requested)) {
    const parsedAssetId = assetId === 'xch' ? '1' : assetId;
    royaltyPercentages.spending[parsedAssetId] = royaltyPercentageForDriverInfo(infos[assetId]);
  }

  for (const assetId of Object.keys(offerSummary.offered)) {
    const parsedAssetId = assetId === 'xch' ? '1' : assetId;
    royaltyPercentages.receiving[parsedAssetId] = royaltyPercentageForDriverInfo(infos[assetId]);
  }

  return royaltyPercentages;
}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L305-309)
```typescript
    const result: DisplayWalletDeltaItem = {
      kind: 'nft',
      nftId,
      royaltyPercentage,
    };
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L311-326)
```typescript
    try {
      const nftInfo = await nftGetInfo(key);
      if (nftInfo && nftInfo.success && nftInfo.nft_info && nftInfo.nft_info.data_uris) {
        const previewUrl = nftInfo.nft_info.data_uris.find((u) => isValidURL(u));

        if (previewUrl) {
          result.previewUrl = previewUrl;
        }

        if ('royalty_percentage' in nftInfo.nft_info) {
          result.royaltyPercentage = parseRoyaltyPercentage(nftInfo.nft_info.royalty_percentage);
        }
      }
    } catch {
      // NFT type has already been resolved from offer data; metadata is best effort.
    }
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L354-375)
```typescript
function formatAmountWithRoyalties(
  line: DisplayWalletDeltaItem,
  amount: bigint,
  royaltyPercentages: number[],
): string | undefined {
  if (royaltyPercentages.length === 0 || line.kind === 'nft') {
    return undefined;
  }

  const splitAmount = amount / BigInt(royaltyPercentages.length);
  const royaltyAmount = royaltyPercentages.reduce(
    (total, royaltyPercentage) => total + (splitAmount * BigInt(royaltyPercentage)) / 10_000n,
    0n,
  );
  const totalAmount = amount + royaltyAmount;

  if (line.kind === 'xch') {
    return mojoToChiaLocaleString(totalAmount);
  }

  return mojoToCATLocaleString(totalAmount);
}
```

**File:** packages/gui/src/electron/api/nftGetInfo.ts (L4-6)
```typescript
  nft_info?: {
    data_uris?: string[];
    data_hash?: string;
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L109-114)
```typescript
        {line.amountWithRoyalties && (
          <div className="text-xs text-chia-text-secondary">
            {i18n._(/* i18n */ { id: 'Total Amount with Royalties' })}: {line.amountWithRoyalties}{' '}
            {networkPrefix ? networkPrefix.toUpperCase() : 'XCH'}
          </div>
        )}
```
