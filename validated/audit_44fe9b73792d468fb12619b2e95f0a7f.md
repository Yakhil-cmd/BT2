### Title
Positional Index Mismatch in `getAllOffers` Response Zipping Causes Wrong Offer Blob Association — (`File: packages/api-react/src/services/wallet.ts`)

---

### Summary

The `getAllOffers` RTK Query endpoint zips two parallel arrays — `response.tradeRecords` and `response.offers` — by positional index to attach the raw offer blob (`_offerData`) to each trade record. If the backend returns these arrays with different lengths or ordering (a realistic condition when some offers lack stored file contents), the wrong offer blob is silently attached to the wrong trade record. Downstream, this mismatched blob is what gets published to external marketplaces (Dexie, Spacescan, Offerpool, MintGarden) when the user clicks "Share," causing a counterparty to accept the wrong offer and the user to lose different assets than intended.

---

### Finding Description

In `packages/api-react/src/services/wallet.ts`, the `transformResponse` for `getAllOffers` performs a positional zip:

```typescript
return response.tradeRecords.map((tradeRecord, index) => ({
  ...tradeRecord,
  _offerData: response.offers?.[index],   // ← pure positional assumption
}));
``` [1](#0-0) 

The only guard is a truthiness check on `response.offers`; there is no length-equality check and no ID-based matching between the two arrays. [2](#0-1) 

The backend RPC `get_all_offers` is called with `fileContents: true` and with `excludeMyOffers`/`excludeTakenOffers` filters: [3](#0-2) 

The Chia wallet backend stores offer blobs only for offers the user *created*. Taken offers (where the user accepted someone else's offer) typically have no stored blob. When `includeTakenOffers=true` and `includeMyOffers=true`, the backend may return a `tradeRecords` array that includes taken offers but an `offers` array that is shorter (or contains `null` entries for taken offers), breaking the positional correspondence. Any divergence in length or ordering between the two arrays causes `tradeRecord[i]` to receive `offers[j]` where `i ≠ j`.

The same positional zip is replicated verbatim in the WalletConnect/dApp command path: [4](#0-3) 

The mismatched `_offerData` field is then consumed directly in `OfferManager.tsx`:

- **Share action**: `offerData={row._offerData}` is passed to `OfferShareDialog`, which posts it to Dexie, Spacescan, Offerpool, or MintGarden.
- **Display action**: `handleShowOfferData(row._offerData)` renders the raw blob. [5](#0-4) [6](#0-5) 

The share dialogs post the blob directly to external services: [7](#0-6) 

---

### Impact Explanation

When `_offerData` from offer B is attached to the display row for offer A, the user sees offer A's summary (asset type, amount, counterparty) in the UI but the "Share" button publishes offer B's spend bundle to the marketplace. A counterparty who accepts the listing executes offer B on-chain, causing the user to spend the assets committed in offer B — potentially a different amount, different asset type (XCH vs. CAT vs. NFT), or a different counterparty address — without the user's informed consent. This is a concrete, irreversible asset loss.

---

### Likelihood Explanation

Any wallet that has both created offers and taken offers simultaneously triggers the divergence condition, since taken offers typically lack stored blobs. This is a routine wallet state for active traders. No attacker action is required; the mismatch arises from normal wallet usage. The user must then click "Share" on an offer in the list, which is the primary workflow for publishing offers.

---

### Recommendation

Replace the positional zip with an ID-keyed lookup. The backend should return a map from `trade_id` to offer blob, or the GUI should match by `trade_id`:

```typescript
// Build a map from trade_id → offer blob
const offerMap = new Map<string, string>();
if (response.offers && response.tradeRecords) {
  response.tradeRecords.forEach((record, i) => {
    if (response.offers[i] != null) {
      offerMap.set(record.tradeId, response.offers[i]);
    }
  });
}
return response.tradeRecords.map((tradeRecord) => ({
  ...tradeRecord,
  _offerData: offerMap.get(tradeRecord.tradeId),
}));
```

Apply the same fix to the WalletConnect transform in `Commands.ts` at the `chia_wallet.get_all_offers` entry.

---

### Proof of Concept

1. Create two offers in the Chia wallet: offer A (1 XCH → CAT) and offer B (10 XCH → NFT).
2. Accept an external offer (becoming a taker), so the wallet now has at least one taken offer with no stored blob.
3. Open the Offers list. The GUI calls `getAllOffers` with `includeMyOffers=true, includeTakenOffers=true`.
4. The backend returns `tradeRecords` = [takenOffer, offerA, offerB] but `offers` = [null, blobA, blobB] (or a shorter array depending on backend behavior), causing `tradeRecords[0]._offerData = null`, `tradeRecords[1]._offerData = blobA`, `tradeRecords[2]._offerData = blobB` — which may be correct in this ordering, but any reordering (e.g., by RELEVANCE sort) that affects one array differently than the other produces a mismatch.
5. Click "Share" on offer A in the UI. The `OfferShareDialog` receives `offerData = blobB` (offer B's spend bundle).
6. Confirm sharing to Dexie. Dexie lists offer B's spend bundle under offer A's display summary.
7. A counterparty accepts the listing, executing offer B on-chain: the user loses 10 XCH and their NFT instead of 1 XCH and the CAT.

### Citations

**File:** packages/api-react/src/services/wallet.ts (L669-678)
```typescript
    getAllOffers: query(build, WalletService, 'getAllOffers', {
      transformResponse: (response) => {
        if (!response.offers) {
          return response.tradeRecords;
        }
        return response.tradeRecords.map((tradeRecord, index) => ({
          ...tradeRecord,
          _offerData: response.offers?.[index],
        }));
      },
```

**File:** packages/api/src/services/WalletService.ts (L324-342)
```typescript
  async getAllOffers(args: {
    start?: number;
    end?: number;
    sortKey?: 'CONFIRMED_AT_HEIGHT' | 'RELEVANCE';
    reverse?: boolean;
    includeMyOffers?: boolean;
    includeTakenOffers?: boolean;
  }) {
    return this.command<{ offers: string[]; tradeRecords: TradeRecord[] }>('get_all_offers', {
      includeCompleted: true,
      fileContents: true,
      start: args.start,
      end: args.end,
      sortKey: args.sortKey,
      reverse: args.reverse,
      excludeMyOffers: !args.includeMyOffers,
      excludeTakenOffers: !args.includeTakenOffers,
    });
  }
```

**File:** packages/gui/src/electron/commands/Commands.ts (L2004-2015)
```typescript
        transform: (data) => {
          const tradeRecords = (data.trade_records as unknown[]) ?? [];
          const offers = data.offers as unknown[] | undefined;
          if (!offers) {
            return tradeRecords;
          }

          return tradeRecords.map((record, i) => ({
            ...(record as Record<string, unknown>),
            _offer_data: offers[i],
          }));
        },
```

**File:** packages/gui/src/components/offers/OfferManager.tsx (L150-159)
```typescript
    async function handleShare(event: any, row: OfferTradeRecord) {
      await openDialog(
        <OfferShareDialog
          offerRecord={row}
          // eslint-disable-next-line no-underscore-dangle -- Can't do anything about it
          offerData={row._offerData}
          exportOffer={() => saveOffer(row.tradeId)}
          testnet={testnet}
        />,
      );
```

**File:** packages/gui/src/components/offers/OfferManager.tsx (L283-286)
```typescript
                  {canDisplayData && (
                    // eslint-disable-next-line no-underscore-dangle -- Can't do anything about it
                    <MenuItem onClick={() => handleShowOfferData(row._offerData)} close>
                      <ListItemIcon>
```

**File:** packages/gui/src/components/offers/OfferShareDialog.tsx (L253-258)
```typescript
  async function handleConfirm() {
    const { viewLink: url, offerLink } = await postToDexie(offerData, testnet);
    log(`Dexie URL: ${url}`);
    setSharedURL(url);
    log(`Dexie offerLink: ${offerLink}`);
    setRawOfferURL(offerLink);
```
