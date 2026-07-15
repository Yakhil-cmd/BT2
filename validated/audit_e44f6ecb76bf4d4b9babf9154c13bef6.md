### Title
NFT Identity Spoofing via Mismatched `infos.launcherId` in Offer Summary — (`packages/gui/src/util/offerToOfferBuilderData.ts`)

### Summary

`offerToOfferBuilderData` derives the displayed NFT ID from `info.launcherId` (sourced from the offer blob's `driver_dict` / RPC `infos` field) rather than from the actual asset key `id` in `offered`/`requested`. Because the Chia offer protocol's `driver_dict` is metadata embedded in the offer blob and is **not** cryptographically committed to the spend bundle, an attacker who crafts the offer blob can set `driver_dict[launcherIdA].launcher_id = launcherIdB`, causing the GUI to display NFT_B while the on-chain transfer encodes NFT_A.

---

### Finding Description

**Root cause — `offerToOfferBuilderData.ts` lines 40–43 and 62–65:**

```typescript
Object.keys(requested).forEach((id) => {
  const info = infos[id];
  ...
  } else if (info?.type === 'singleton') {
    offeredNfts.push({
      nftId: launcherIdToNFTId(info.launcherId),  // ← uses info.launcherId, NOT id
    });
  }
``` [1](#0-0) [2](#0-1) 

There is no assertion that `info.launcherId === id`. The key `id` is the actual asset being transferred (from `offered`/`requested`); `info.launcherId` is whatever the offer blob's `driver_dict` says.

**Import path — `OfferBuilderImport.tsx`:**

The user drops/pastes an offer blob. `parseOfferSummary` calls `getOfferSummary({ offerData })`, receives the RPC summary (including `infos`), and navigates to the viewer passing both `offerData` and `offerSummary` as router state — no cross-validation between them. [3](#0-2) 

**Viewer — `OfferBuilderViewer.tsx`:**

`computedOfferBuilderData` is derived entirely from `offerSummary` (which contains the attacker-controlled `infos`). The `OfferBuilder` renders with this data, so `OfferBuilderNFT` receives NFT_B's `nftId` as its field value. [4](#0-3) 

**Accept path — `useAcceptOfferHook.tsx` line 95:**

When the user clicks Accept, `takeOffer({ offer: offerData, ... })` is called with the **original offer blob** — which encodes NFT_A. The displayed NFT_B and the on-chain NFT_A are permanently decoupled. [5](#0-4) 

**`OfferBuilderNFT` renders from the spoofed `nftId`:** [6](#0-5) 

---

### Impact Explanation

A victim who imports a crafted offer sees NFT_B (high-value) displayed in the offer UI but, upon acceptance, receives NFT_A (low-value). This is a direct asset-loss scenario: the user pays XCH/CAT for an NFT they did not receive. The `nftId` text field, the NFT preview card, and the minter DID display all derive from the spoofed `info.launcherId`.

---

### Likelihood Explanation

**Precondition dependency (critical caveat):** The attack requires the Chia wallet daemon's `get_offer_summary` RPC to return the `driver_dict`'s `launcher_id` field as-is without cross-validating it against the spend bundle's coin spends. The Chia offer protocol embeds `driver_dict` as unsigned metadata in the offer blob, so this is the expected daemon behavior — but it cannot be confirmed from GUI code alone. If the daemon independently recomputes `launcher_id` from the spend bundle, the attack is blocked at the RPC layer.

Assuming the daemon returns `driver_dict` verbatim (consistent with the Chia offer spec), the attack is straightforward: craft a valid offer blob for NFT_A, set `driver_dict[launcherIdA].launcher_id = "0x" + launcherIdB`, encode as bech32m, share with victim.

**Visual impact caveat:** `useNFT` reads from `NFTProviderContext`. [7](#0-6) 

If the provider only serves NFTs in the user's local wallet, the preview card shows "NFT not specified" for NFT_B (since it is not the user's NFT). However, the **NFT ID text field** still displays NFT_B's bech32m ID — which is the primary spoofing surface. A user who copies that ID to verify it externally would be misled.

---

### Recommendation

In `offerToOfferBuilderData.ts`, derive the NFT ID from the asset key `id` (which comes from the cryptographically-committed `offered`/`requested` fields), not from `info.launcherId`:

```typescript
} else if (info?.type === 'singleton') {
  offeredNfts.push({
    nftId: launcherIdToNFTId(id),  // use id, not info.launcherId
  });
}
``` [8](#0-7) [9](#0-8) 

Additionally, add a cross-check in `parseOfferSummary` / `OfferBuilderImport` that asserts `info.launcherId` (normalized, stripped of `0x`) matches the map key for every singleton entry before navigating to the viewer.

---

### Proof of Concept

1. Obtain a valid offer blob for NFT_A (low-value NFT you own).
2. Decode the bech32m offer blob, locate the `driver_dict` field.
3. Change `driver_dict[launcherIdA].launcher_id` to `"0x" + launcherIdB` (a high-value NFT's launcher ID). Leave `offered`/`requested` unchanged (still reference `launcherIdA`).
4. Re-encode as bech32m with `offer1` prefix.
5. Share the crafted offer with a victim.
6. Victim imports via `OfferBuilderImport` → `parseOfferSummary` → `getOfferSummary` returns `infos[launcherIdA].launcherId = launcherIdB`.
7. `offerToOfferBuilderData` pushes `nftId: launcherIdToNFTId(launcherIdB)` → viewer displays NFT_B's ID.
8. Victim accepts → `takeOffer({ offer: originalBlob })` → on-chain transfer of NFT_A.

**Invariant violated:** The NFT ID shown in the offer viewer (`launcherIdToNFTId(info.launcherId)`) does not match the NFT actually encoded in the offer blob (`launcherIdToNFTId(id)`). [8](#0-7) [10](#0-9) [11](#0-10) [5](#0-4)

### Citations

**File:** packages/gui/src/util/offerToOfferBuilderData.ts (L29-48)
```typescript
  Object.keys(requested).forEach((id) => {
    const amount = new BigNumber(requested[id]);
    const info = infos[id];

    if (info?.type === 'CAT') {
      const crCat = extractCrCatData(info);
      offeredTokens.push({
        amount: mojoToCAT(amount).toFixed(),
        assetId: id,
        crCat,
      });
    } else if (info?.type === 'singleton') {
      offeredNfts.push({
        nftId: launcherIdToNFTId(info.launcherId),
      });
    } else if (id === 'xch') {
      offeredXch.push({
        amount: mojoToChia(amount).toFixed(),
      });
    }
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

**File:** packages/gui/src/components/offers2/OfferBuilderImport.tsx (L34-53)
```typescript
  async function parseOfferSummary(rawOfferData: string) {
    const [offerData] = parseOfferData(rawOfferData);
    if (!offerData) {
      throw new Error(t`Could not parse offer data`);
    }

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

**File:** packages/gui/src/components/offers2/OfferBuilderViewer.tsx (L156-171)
```typescript
  const computedOfferBuilderData = useMemo(() => {
    if (!offerSummaryStringified || isDataLayer) {
      return undefined;
    }

    const offerSummaryParsed = JSON.parse(offerSummaryStringified);
    if (!offerSummaryParsed) {
      return undefined;
    }
    try {
      return offerToOfferBuilderData(offerSummaryParsed, setDefaultOfferedFee, fee);
    } catch (e) {
      setError(e);
      return undefined;
    }
  }, [offerSummaryStringified, setDefaultOfferedFee, fee, isDataLayer]);
```

**File:** packages/gui/src/hooks/useAcceptOfferHook.tsx (L43-52)
```typescript
    const offerBuilderData = offerToOfferBuilderData(offerSummary, true);
    const { assetsToUnlock } = await offerBuilderDataToOffer({
      data: offerBuilderData,
      wallets,
      offers: offers || [],
      validateOnly: false,
      considerNftRoyalty: true,
      allowEmptyOfferColumn: true, // When accepting a one-sided offer, nothing is required in the offer column
      allowUnknownRequestedCATs: true, // When accepting an offer containing unknown CATs, we can still accept it
    });
```

**File:** packages/gui/src/hooks/useAcceptOfferHook.tsx (L92-96)
```typescript
    try {
      onUpdate?.(true);

      const response = await takeOffer({ offer: offerData, fee: feeInMojos }).unwrap();

```

**File:** packages/gui/src/components/offers2/OfferBuilderNFT.tsx (L38-44)
```typescript
  const fieldName = `${name}.nftId`;
  const value = useWatch({
    name: fieldName,
  });

  const { didId: minterDID, didName: minterDIDName } = useNFTMinterDID(value);
  const { nft, isLoading, error } = useNFT(value);
```

**File:** packages/gui/src/hooks/useNFT.ts (L5-14)
```typescript
export default function useNFT(id?: string) {
  const context = useContext(NFTProviderContext);
  if (!context) {
    throw new Error('useNFT must be used within NFTProvider');
  }

  const { invalidate, getNFT, subscribeToNFTChanges } = context;

  const handleInvalidate = useCallback(() => invalidate(id), [invalidate, id]);
  const [nftState, setNFTState] = useState(() => getNFT(id));
```
