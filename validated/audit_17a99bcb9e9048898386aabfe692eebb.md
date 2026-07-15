Let me check the `NFTHashStatus` component and how `NFTPreview` is used in the offer dialog context.

### Title
Unverified NFT Content Rendered in Offer Preview Despite Hash Mismatch — (`packages/gui/src/components/nfts/NFTPreview.tsx`)

### Summary

`NFTPreview`'s `preparePreview` function renders NFT artwork from a `cache://` URI without checking whether hash verification succeeded. An attacker who controls the URI server can serve tampered content that will be displayed in the offer-accept dialog even though `useNFTVerifyHash` detected a hash mismatch.

---

### Finding Description

The call chain is:

**Step 1 — `useNFTVerifyHash` detects mismatch but still returns the URI**

`findValidUri` calls `getChecksum(uri)` and compares it to the on-chain hash. When they don't match it throws `'Invalid hash checksum'`, catches it, and stores `{ isVerified: false, uri }` as `first`. The `previewState` memo then falls through all `isVerified` guards and returns the unverified state via the final fallback: [1](#0-0) 

**Step 2 — `preparePreview` renders without checking `isVerified`**

`preparePreview` receives `preview` (which may have `isVerified: false`) and calls `getURI(preview.uri)`. The only gate is whether the returned string starts with `cache://` — there is no check on `preview.isVerified`: [2](#0-1) 

**Step 3 — `CacheManager.getURI` returns `cache://` for any successfully downloaded content**

`getURI` calls `fetchRemoteContent`, which downloads and stores the file, then returns `cache://<filename>` when state is `CACHED`. It performs no hash comparison: [3](#0-2) 

Because `getChecksum` (called by `useNFTVerifyHash`) already triggered `fetchRemoteContent` and cached the file, the subsequent `getURI` call in `preparePreview` hits the already-cached tampered content and immediately returns `cache://...`, passing the `startsWith` check and causing the tampered image/video to be rendered in `SandboxedIframe`.

**Step 4 — The tampered preview is shown in the offer dialog**

`NFTOfferPreview` → `NFTCard` → `NFTPreview` with `preview` prop set: [4](#0-3) 

`NFTHashStatus` is overlaid on the preview (unless `hideStatus` or `isCompact` suppress it): [5](#0-4) 

The hash-status badge is a small overlay that many users will not notice or understand. The tampered artwork occupies the full preview card and is the dominant visual signal at offer-acceptance time.

---

### Impact Explanation

A user viewing an incoming NFT offer sees attacker-chosen artwork instead of the content that was hashed at mint time. This directly satisfies the High-impact criterion: *"Corruption, spoofing, or unsafe trust of NFT metadata… that causes a user to… display the wrong asset… causing the user to approve based on misleading visual content."*

---

### Likelihood Explanation

The attacker only needs to control the HTTP server at one of the NFT's `dataUris` / `preview_image_uris`. This is realistic for:
- The original NFT creator who later swaps the hosted file ("rug" scenario).
- A network-level MITM on an HTTP (non-TLS) URI.

No local access, leaked keys, or dependency compromise is required.

---

### Recommendation

In `preparePreview`, gate rendering on `preview.isVerified`:

```typescript
// packages/gui/src/components/nfts/NFTPreview.tsx
if (!preview?.uri || !preview.isVerified) {
  setPreviewContent(undefined, signal);
  return;
}
```

Alternatively, expose `isVerified` from `useNFTVerifyHash` and pass it as a prop so callers can decide whether to render or show a placeholder.

---

### Proof of Concept

1. Create an NFT whose `dataUris[0]` points to a server you control. Record the SHA-256 of the original file as `dataHash` on-chain.
2. After minting, replace the file at that URI with different content (different image).
3. Open the Chia GUI and view an offer for that NFT.
4. Observe: the replacement image is displayed in the offer preview card. `useNFTVerifyHash` sets `isVerified: false` (hash mismatch), but `preparePreview` still calls `getURI` and renders the cached tampered file.
5. Assert: the `NFTHashStatus` badge appears but the tampered artwork is the dominant visual; a user can click "Accept Offer" while seeing the wrong image.

### Citations

**File:** packages/gui/src/hooks/useNFTVerifyHash.ts (L139-153)
```typescript
  const previewState = useMemo(() => {
    if (previewVideo?.isVerified) {
      return previewVideo;
    }

    if (previewImage?.isVerified) {
      return previewImage;
    }

    if (data?.isVerified) {
      return data;
    }

    return previewVideo || previewImage || data;
  }, [previewVideo, previewImage, data]);
```

**File:** packages/gui/src/components/nfts/NFTPreview.tsx (L213-235)
```typescript
        const cachedURI = await getURI(preview.uri);
        if (!cachedURI || !cachedURI.startsWith('cache://')) {
          setPreviewContent(undefined, signal);
          return;
        }

        setPreviewContent(
          <>
            <style>{style}</style>
            {previewFileType === FileType.VIDEO ? (
              <video width="100%" height="100%" controls={!disableInteractions}>
                <source src={cachedURI} />
              </video>
            ) : previewFileType === FileType.AUDIO ? (
              <audio className={isDarkMode ? 'dark' : ''} controls={!disableInteractions}>
                <source src={cachedURI} />
              </audio>
            ) : (
              <img src={cachedURI} alt={t`Preview`} width="100%" height="100%" />
            )}
          </>,
          signal,
        );
```

**File:** packages/gui/src/components/nfts/NFTPreview.tsx (L398-412)
```typescript
      {!isCompact && !hideStatus && (
        <Box
          sx={{
            display: 'flex',
            position: 'absolute',
            top: 16,
            left: 16,
            right: 16,
            justifyContent: 'center',
            zIndex: 1,
          }}
        >
          <NFTHashStatus nftId={nftId} hideValid />
        </Box>
      )}
```

**File:** packages/gui/src/electron/CacheManager.ts (L489-516)
```typescript
  async getURI(
    url: string,
    options?: {
      maxSize?: number;
      timeout?: number;
    },
  ) {
    if (!isValidURL(url)) {
      throw new Error(`Invalid URL: ${url}`);
    }

    const cacheInfo = await this.fetchRemoteContent(url, options);

    if (cacheInfo.state === CacheState.ERROR) {
      throw new Error(cacheInfo.error);
    }

    if (cacheInfo.state === CacheState.NOT_CACHED) {
      throw new Error('Url is not cached');
    }

    if (cacheInfo.state === CacheState.CACHED) {
      const filePath = this.getCacheFilePath(url);
      return `${CACHE_PROTOCOL}://${path.basename(filePath)}`;
    }

    throw new Error('Unknown cache state');
  }
```

**File:** packages/gui/src/components/nfts/NFTCard.tsx (L80-81)
```typescript
          <NFTPreview id={nftId} disableInteractions={isOffer} ratio={ratio} preview />
        </CardActionArea>
```
