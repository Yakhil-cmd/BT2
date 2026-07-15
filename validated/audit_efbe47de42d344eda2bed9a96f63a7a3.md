### Title
NFT Metadata Fetched Without Integrity Verification When `metadataHash` Is Absent, Enabling Preview Spoofing in Offer Acceptance Flow - (File: packages/gui/src/hooks/useFetchAndProcessMetadata.ts)

---

### Summary

When an NFT is minted without a `metadataHash` (or with an empty string hash), the Chia GUI fetches and unconditionally trusts the metadata JSON from the external `metadataUris` endpoint with no integrity check. An unprivileged attacker who mints such an NFT and controls the metadata server can silently swap the displayed NFT name and preview image at any time. A victim viewing an offer in the GUI sees the spoofed identity — no warning is shown — and may accept the offer, paying real XCH for a worthless NFT.

---

### Finding Description

**Root cause — conditional hash skip in `useFetchAndProcessMetadata`:** [1](#0-0) 

```typescript
if (hash && !compareChecksums(checksum, hash)) {
  throw new Error('Checksum mismatch');
}
```

The guard is `if (hash && …)`. When `metadataHash` is an empty string (`""`) or `undefined`, the condition short-circuits and the downloaded metadata JSON is accepted with no integrity check. The `metadataHash` field on `NFTInfo` is typed as `string` but is legitimately absent or empty for NFTs minted without one. [2](#0-1) 

**How metadata is fetched — the hash is passed through from the on-chain record:** [3](#0-2) 

`metadataHash` is read directly from the wallet RPC response and forwarded to `fetchAndProcessMetadata`. If it is falsy, no checksum comparison occurs and the JSON from the external server is parsed and stored as authoritative metadata.

**What the unverified metadata controls:** [4](#0-3) 

The metadata JSON supplies `name`, `description`, `preview_image_uris`, `preview_image_hash`, `preview_video_uris`, and `preview_video_hash`. While `useNFTVerifyHash` does verify the preview image against `preview_image_hash` from the metadata, that hash itself comes from the unverified metadata — so an attacker who controls the metadata server controls both the preview URI and its expected hash, making the inner verification meaningless. [5](#0-4) 

**No warning is surfaced to the user:**

`NFTHashStatus` only checks `dataHash` (the main NFT content hash), not `metadataHash`. When `dataHash` is valid, the component is hidden entirely via `hideValid`: [6](#0-5) 

A user viewing an offer for an NFT with a valid `dataHash` but absent `metadataHash` sees no warning chip at all, while the displayed name and preview image are fully attacker-controlled.

---

### Impact Explanation

**High** — Corruption/spoofing of NFT metadata in the offer acceptance flow causes a user to display the wrong asset identity. The user sees a convincing name and preview image for an NFT they are about to purchase, but those are served from an attacker-controlled server with no on-chain binding. The user approves and pays XCH for a worthless NFT. This matches: *"Corruption, spoofing, or unsafe trust of… NFT metadata… that causes a user to approve… the wrong asset, identity, amount, destination, or status."*

---

### Likelihood Explanation

**Medium.** The attacker only needs to:
1. Mint an NFT with an empty `metadataHash` and `metadataUris` pointing to their server (costs a small XCH fee; no special privilege required).
2. Operate a web server that serves different metadata when the victim views the offer.

No key compromise, MITM, or host compromise is required. The attack is passive once the offer is distributed.

---

### Recommendation

1. **Treat absent `metadataHash` as unverified and surface a distinct warning** in the offer viewer and NFT detail view — separate from the `dataHash` status chip — so users know the displayed name and preview are not integrity-protected.
2. **In `useFetchAndProcessMetadata`**, consider rejecting or flagging metadata when `hash` is falsy rather than silently accepting it, at least in security-sensitive contexts (offer acceptance).
3. **In `useNFTVerifyHash`**, propagate a `metadataHashMissing` flag so `NFTHashStatus` can render a distinct "Metadata unverified" indicator even when `dataHash` is valid.

---

### Proof of Concept

1. Attacker mints an NFT with `metadataHash = ""` (empty) and `metadataUris = ["https://attacker.com/meta.json"]`. A valid `dataHash` is provided for some innocuous content so the data-hash chip shows green or is hidden.
2. Attacker creates an offer: sell this NFT for 10 XCH and distributes it (e.g., via a WalletConnect `chia_showNotification` offer push or a shared offer file).
3. Attacker's server responds to `GET /meta.json` with:
   ```json
   {
     "name": "Rare CryptoPunk #1",
     "preview_image_uris": ["https://attacker.com/fake-punk.png"],
     "preview_image_hash": "<sha256 of fake-punk.png>"
   }
   ```
4. Victim opens the offer in the GUI. `useFetchAndProcessMetadata` fetches the metadata; the `if (hash && …)` guard is skipped because `metadataHash` is `""`. The metadata is stored as authoritative.
5. `useNFTVerifyHash` fetches `fake-punk.png` and verifies it against the attacker-supplied `preview_image_hash` — this passes, so `previewImage.isVerified = true`.
6. `NFTPreview` renders the fake punk image with `isVerified: true`. `NFTHashStatus` is hidden (`hideValid=true`, `dataHash` is valid). No warning is shown.
7. Victim sees "Rare CryptoPunk #1" with a convincing preview, accepts the offer, and pays 10 XCH for a worthless NFT. [7](#0-6) [8](#0-7)

### Citations

**File:** packages/gui/src/hooks/useFetchAndProcessMetadata.ts (L16-33)
```typescript
  const fetchAndProcessMetadata = useCallback(
    async (uri: string, hash: string | undefined) => {
      log(`Fetching metadata from ${uri}`);

      const checksum = await getChecksum(uri);

      log(`Comparing checksums ${checksum} and ${hash}`);
      if (hash && !compareChecksums(checksum, hash)) {
        throw new Error('Checksum mismatch');
      }

      const headers = await getHeaders(uri);
      const content = await getContent(uri);

      const metadataString = parseFileContent(content, headers);

      return JSON.parse(metadataString) as Metadata;
    },
```

**File:** packages/api/src/@types/NFTInfo.ts (L13-14)
```typescript
  metadataHash: string;
  metadataUris: string[];
```

**File:** packages/gui/src/components/nfts/provider/hooks/useMetadataData.ts (L76-83)
```typescript
          const { metadataUris = [], metadataHash } = nft;

          const [firstUri] = metadataUris;
          if (!firstUri) {
            throw new Error('No metadata URI');
          }

          const metadata = await fetchAndProcessMetadata(firstUri, metadataHash);
```

**File:** packages/gui/src/@types/Metadata.ts (L1-24)
```typescript
type Metadata = {
  attributes?: {
    trait_type: string;
    value: string;
  }[];
  collection?: {
    name: string;
    id: string;
    attributes: {
      trait_type: string;
      value: string;
    }[];
  };
  description?: string;
  image?: string;
  format?: string;
  name?: string;
  sensitive_content?: 'false' | 'true' | true | false;
  minting_tool?: string;
  preview_video_uris?: string[];
  preview_video_hash?: string;
  preview_image_uris?: string[];
  preview_image_hash?: string;
};
```

**File:** packages/gui/src/hooks/useNFTVerifyHash.ts (L43-51)
```typescript
  const findValidUri = useCallback(
    async (
      uris: string[] | undefined,
      hash: string | undefined,
      onlyFirst: boolean = false,
    ): Promise<PreviewState | undefined> => {
      if (!uris || !uris.length || !hash) {
        return undefined;
      }
```

**File:** packages/gui/src/hooks/useNFTVerifyHash.ts (L109-118)
```typescript
        const { preview_video_uris: previewVideoUris, preview_video_hash: previewVideoHash } = nftMetadata;

        const videoState = await findValidUri(previewVideoUris, previewVideoHash);
        setPreviewVideo(videoState);

        if (!videoState?.isVerified) {
          const { preview_image_uris: previewImageUris, preview_image_hash: previewImageHash } = nftMetadata;
          const imageState = await findValidUri(previewImageUris, previewImageHash);
          setPreviewImage(imageState);
        }
```

**File:** packages/gui/src/components/nfts/NFTPreview.tsx (L398-411)
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
```
