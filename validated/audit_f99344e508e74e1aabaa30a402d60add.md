### Title
Crafted Offer Blob with Misclassified `singleton` Driver Suppresses Unknown-CAT Warning in `OfferBuilderViewer` — (`packages/gui/src/components/offers2/OfferBuilderImport.tsx`, `packages/gui/src/components/offers/OfferImport.tsx`)

---

### Summary

The GUI unconditionally trusts the `infos` field returned by the `get_offer_summary` RPC. An attacker can embed a driver dict in an offer blob that labels a CAT asset ID as `type: 'singleton'`. This causes `offerToOfferBuilderData` to route the asset into the NFT bucket instead of the token bucket, which silently suppresses both the per-viewer "unknown token" alert and the per-token "Unknown CAT" inline warning. The user is shown an NFT UI for what is actually a worthless CAT, with no protective warning, and can accept the offer.

---

### Finding Description

**Entry point — `OfferBuilderImport.tsx`**

`parseOfferSummary` calls `getOfferSummary` and passes the raw RPC response directly to the router state with no validation of the `infos` field: [1](#0-0) 

The summary is then consumed by `OfferBuilderViewer` via the `/dashboard/offers/view` route.

**Secondary entry point — `OfferImport.tsx`**

The older import path additionally uses `offerContainsAssetOfType(offerSummary, 'singleton')` to decide whether to route to the NFT viewer (`/dashboard/offers/view-nft`) or the standard viewer: [2](#0-1) 

`offerContainsAssetOfType` reads `infos[assetId].type` directly from the RPC response with no on-chain cross-check: [3](#0-2) 

**Warning suppression in `offerToOfferBuilderData`**

When `info?.type === 'singleton'`, the asset is placed into `requestedNfts` instead of `requestedTokens`: [4](#0-3) 

**`OfferBuilderViewer` — `missingRequestedCATs` bypass**

`getUnknownCATs` is called only on `computedOfferBuilderData.requested.tokens`. Because the misclassified CAT is in `requestedNfts`, it is never passed to `getUnknownCATs`, so `missingRequestedCATs` is `false` and the warning banner is never rendered: [5](#0-4) 

**`OfferBuilderProvider` — per-token "Unknown CAT" bypass**

The same pattern repeats inside `OfferBuilderProvider`, which feeds `requestedUnknownCATs` into the context consumed by `OfferBuilderValue`/`OfferBuilderToken`. Because the misclassified CAT is absent from `requestedTokens`, the inline "Unknown CAT" tooltip warning is also suppressed: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

An attacker who controls the offer blob (shared via file, paste, QR, or notification URL) can suppress every unknown-CAT guard in the GUI. The victim sees an NFT section with a bech32m-encoded NFT ID derived from the CAT asset ID, no "Unknown CAT" warning, and no "verify asset IDs" banner. If the victim accepts, they give XCH (or another asset) and receive a worthless CAT. The actual spend bundle is determined by the offer blob, not the UI display, so the on-chain outcome matches the attacker's intent.

This satisfies the High impact category: *"Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status."*

---

### Likelihood Explanation

- The offer blob format is public and the driver dict is attacker-controlled.
- The attack requires only that the victim import a crafted offer file or paste a crafted blob — a normal user workflow.
- The NFT preview will fail to load (no real NFT on-chain), which is a partial mitigating signal, but NFT previews routinely fail for legitimate reasons (IPFS unavailability, slow networks), so a non-technical user may not treat it as a red flag.
- No local compromise, leaked keys, or cryptographic break is required.

---

### Recommendation

1. **Validate `infos.type` against the actual asset structure.** For a `singleton` entry, verify that `infos[assetId].launcherId` matches `assetId` (the launcher ID is the asset ID for NFTs). Reject or downgrade entries where the claimed type is inconsistent.
2. **Cross-check `infos` against the `offered`/`requested` keys.** Any asset ID present in `offered` or `requested` but absent from `infos`, or whose `infos` type is unrecognised, should be treated as an unknown CAT, not silently dropped from the warning path.
3. **Treat unrecognised/unresolvable NFT IDs as a warning condition.** If `launcherIdToNFTId` produces an ID that cannot be resolved by the NFT info API, surface a warning rather than silently showing an empty NFT slot.

---

### Proof of Concept

1. Craft an offer blob whose spend bundle driver dict contains:
   ```json
   {
     "<cat_asset_id>": {
       "type": "singleton",
       "launcher_id": "0x<cat_asset_id>"
     }
   }
   ```
   where `<cat_asset_id>` is a worthless CAT the attacker controls, placed in the `offered` side (taker receives it).
2. Import the blob via `OfferBuilderImport` (drag-and-drop or Ctrl-V paste).
3. `getOfferSummary` returns `infos: { <cat_asset_id>: { type: 'singleton', launcher_id: '<cat_asset_id>' } }`.
4. `offerToOfferBuilderData` places the asset in `requestedNfts`; `requested.tokens` is empty.
5. Assert: `missingRequestedCATs === false`, no "Unknown CAT" warning is shown, the UI displays an NFT section with a non-resolving NFT ID.
6. Click "Accept Offer" — the transaction executes, giving XCH and receiving the worthless CAT.

### Citations

**File:** packages/gui/src/components/offers2/OfferBuilderImport.tsx (L40-53)
```typescript
    const { summary } = await getOfferSummary({ offerData }).unwrap();

    if (summary) {
      navigate('/dashboard/offers/view', {
        state: {
          offerData,
          offerSummary: summary,
          imported: true,
          referrerPath: '/dashboard/offers',
        },
      });
    } else {
      console.warn('Unable to parse offer data');
    }
```

**File:** packages/gui/src/components/offers/OfferImport.tsx (L52-64)
```typescript
    if (offerSummary) {
      let navigationPath: string;
      if (isDataLayerOfferSummary(offerSummary)) {
        navigationPath = '/dashboard/offers/view';
      } else {
        navigationPath = offerContainsAssetOfType(offerSummary, 'singleton')
          ? '/dashboard/offers/view-nft'
          : '/dashboard/offers/view';
      }

      navigate(navigationPath, {
        state: { offerData, offerSummary, offerFilePath, imported: true },
      });
```

**File:** packages/gui/src/components/offers/utils.ts (L162-188)
```typescript
export function offerContainsAssetOfType(
  offerSummary: OfferSummaryRecord,
  assetType: string,
  side?: 'offered' | 'requested',
): boolean {
  const { infos } = offerSummary;
  if (!infos) {
    return false;
  }
  const matchingAssetIds: string[] = Object.keys(infos).filter((assetId) => {
    const info: OfferSummaryAssetInfo = infos[assetId];
    return info.type === assetType;
  });

  let keys: string[] = [];
  if (side) {
    keys = Object.keys(offerSummary[side]);
  } else {
    keys = [...Object.keys(offerSummary.offered), ...Object.keys(offerSummary.requested)];
  }

  return (
    !!matchingAssetIds &&
    matchingAssetIds.length > 0 &&
    // Sanity check that at least one matchingAssetId is in the requested set of keys
    matchingAssetIds.some((matchingAssetId) => keys.includes(matchingAssetId))
  );
```

**File:** packages/gui/src/util/offerToOfferBuilderData.ts (L51-71)
```typescript
  Object.keys(offered).forEach((id) => {
    const amount = new BigNumber(offered[id]);
    const info = infos[id];

    if (info?.type === 'CAT') {
      const crCat = extractCrCatData(info);
      requestedTokens.push({
        amount: mojoToCAT(amount).toFixed(),
        assetId: id,
        crCat,
      });
    } else if (info?.type === 'singleton') {
      requestedNfts.push({
        nftId: launcherIdToNFTId(info.launcherId),
      });
    } else if (id === 'xch') {
      requestedXch.push({
        amount: mojoToChia(amount).toFixed(),
      });
    }
  });
```

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L173-194)
```typescript
  const [offeredUnknownCATs, requestedUnknownCATs] = useMemo(() => {
    if (!computedOfferBuilderData || !wallets) {
      return [];
    }

    const offeredUnknownCATsLocal = getUnknownCATs(
      wallets,
      computedOfferBuilderData.offered.tokens.map(({ assetId }) => assetId),
    );
    const requestedUnknownCATsLocal = getUnknownCATs(
      wallets,
      computedOfferBuilderData.requested.tokens.map(({ assetId }) => assetId),
    );

    return [offeredUnknownCATsLocal, requestedUnknownCATsLocal];
  }, [computedOfferBuilderData, wallets]);

  const missingOfferedCATs = !!offeredUnknownCATs?.length;
  const missingRequestedCATs = !!requestedUnknownCATs?.length;

  const canAccept = !!offerData;
  const disableAccept = missingOfferedCATs || showInvalid || isExpired;
```

**File:** packages/gui/src/components/offers2/OfferBuilderProvider.tsx (L55-70)
```typescript
  const [offeredUnknownCATs, requestedUnknownCATs] = useMemo(() => {
    if ((!offeredTokens && !requestedTokens) || !wallets) {
      return [];
    }

    const offeredUnknownCATsLocal = getUnknownCATs(
      wallets,
      offeredTokens.map(({ assetId }) => assetId),
    );
    const requestedUnknownCATsLocal = getUnknownCATs(
      wallets,
      requestedTokens.map(({ assetId }) => assetId),
    );

    return [offeredUnknownCATsLocal, requestedUnknownCATsLocal];
  }, [offeredTokens, requestedTokens, wallets]);
```

**File:** packages/gui/src/components/offers2/OfferBuilderValue.tsx (L209-229)
```typescript
      {warnUnknownCAT && (
        <Flex gap={0.5} alignItems="center">
          <Typography variant="body2" color={StateColor.WARNING}>
            Unknown CAT
          </Typography>
          <TooltipIcon>
            {offeredUnknownCATs?.includes(value) ? (
              <Typography variant="caption" color="textSecondary">
                <Trans>Offer cannot be accepted because you don&apos;t possess the requested assets</Trans>
              </Typography>
            ) : requestedUnknownCATs?.includes(value) ? (
              <Typography variant="caption" color="textSecondary">
                <Trans>
                  Warning: Verify that the offered CAT asset IDs match the asset IDs of the tokens you expect to
                  receive.
                </Trans>
              </Typography>
            ) : null}
          </TooltipIcon>
        </Flex>
      )}
```
