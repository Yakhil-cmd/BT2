### Title
NFT Metadata Hash Verification Silently Bypassed When `metadataHash` Is Absent, Enabling Arbitrary Metadata Spoofing in Offer Flows - (File: `packages/gui/src/hooks/useFetchAndProcessMetadata.ts`)

### Summary
`fetchAndProcessMetadata` skips its integrity check entirely when the NFT's `metadataHash` is falsy (undefined / null / empty string). An unprivileged attacker who mints an NFT without a metadata hash controls the metadata server and can serve arbitrary JSON — false name, false collection, false description — which the GUI renders without any warning in the NFT offer viewer. A victim who reviews and accepts an offer based on that spoofed metadata approves a transaction for the wrong asset identity.

### Finding Description
In `packages/gui/src/hooks/useFetchAndProcessMetadata.ts` the guard that enforces metadata integrity is:

```typescript
// line 23
if (hash && !compareChecksums(checksum, hash)) {
  throw new Error('Checksum mismatch');
}
``` [1](#0-0) 

When `hash` is falsy the entire `compareChecksums` call is skipped. The function then unconditionally fetches, parses, and returns whatever JSON the remote server provides. [2](#0-1) 

The caller, `useMetadataData`, extracts `metadataHash` directly from the NFT's on-chain record and passes it as-is:

```typescript
const { metadataUris = [], metadataHash } = nft;
const metadata = await fetchAndProcessMetadata(firstUri, metadataHash);
``` [3](#0-2) 

NFTs minted without a metadata hash have `metadataHash = undefined`. In that case `hash` is falsy, the loop-equivalent guard is skipped, and any content served at the metadata URI is accepted as authoritative.

The `NFTHashStatus` component only verifies the NFT's **data** hash (`dataHash` / `dataUris`), not the metadata hash:

```typescript
async function validateData() {
  const dataState = await findValidUri(dataUris, dataHash);
  setData(dataState);
}
``` [4](#0-3) 

So if the NFT has a valid `dataHash` the UI shows "Hash matches" — giving the user a false sense of full verification — while the metadata is completely unverified and attacker-controlled.

### Impact Explanation
The spoofed metadata (name, collection, description, preview image URIs) is rendered directly in the NFT offer viewer (`NFTOfferViewer`, `NFTOfferSummary`) and the NFT gallery. A victim reviewing an incoming offer sees a fabricated identity for the NFT — e.g., a name and collection that impersonates a high-value project — and may accept the offer believing they are acquiring a valuable asset. This satisfies the **High** impact criterion: *"Corruption, spoofing, or unsafe trust of NFT metadata that causes a user to approve… the wrong asset, identity, amount, destination, or status."* [5](#0-4) 

### Likelihood Explanation
Minting an NFT without a metadata hash is a standard, permissionless operation on the Chia network. The attacker controls both the NFT and the metadata server. No leaked keys, host compromise, or cryptographic break is required. The victim only needs to view an offer that references the attacker's NFT — a normal user action on any NFT marketplace or via a shared offer file.

### Recommendation
Remove the short-circuit `hash &&` prefix so that the checksum is always compared when a URI is present:

```typescript
// Before (vulnerable):
if (hash && !compareChecksums(checksum, hash)) {
  throw new Error('Checksum mismatch');
}

// After (safe):
if (!hash || !compareChecksums(checksum, hash)) {
  throw new Error('Metadata hash missing or checksum mismatch');
}
```

Alternatively, refuse to render metadata at all when `metadataHash` is absent, and display an explicit "Unverified metadata" warning in the offer viewer and NFT gallery when the metadata hash is missing.

### Proof of Concept
1. Attacker mints an NFT on Chia with `metadata_hash = None` (no metadata hash) and sets `metadata_uris` to a server they control.
2. Attacker's server initially serves legitimate-looking metadata (e.g., `{"name":"Famous Collection #1","description":"..."}`).
3. Attacker creates an offer for the NFT and shares the offer file.
4. Victim opens the offer in the Chia GUI. `useMetadataData` calls `fetchAndProcessMetadata(firstUri, undefined)`. Because `hash` is `undefined`, line 23 is skipped. The attacker's JSON is parsed and returned.
5. The NFT's `dataHash` is valid, so `NFTHashStatus` shows "Hash matches" — no warning is displayed about the metadata.
6. The victim sees the spoofed name/collection in `NFTOfferViewer` and accepts the offer, transferring XCH/CAT for an NFT whose displayed identity is entirely fabricated.
7. At any point after minting, the attacker can also change the metadata server's response to different content; the GUI will accept the new content without any integrity check.

### Citations

**File:** packages/gui/src/hooks/useFetchAndProcessMetadata.ts (L17-33)
```typescript
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

**File:** packages/gui/src/components/nfts/provider/hooks/useMetadataData.ts (L76-84)
```typescript
          const { metadataUris = [], metadataHash } = nft;

          const [firstUri] = metadataUris;
          if (!firstUri) {
            throw new Error('No metadata URI');
          }

          const metadata = await fetchAndProcessMetadata(firstUri, metadataHash);
          setMetadataOnDemand(nftId, { metadata });
```

**File:** packages/gui/src/hooks/useNFTVerifyHash.ts (L99-102)
```typescript
      async function validateData() {
        const dataState = await findValidUri(dataUris, dataHash);
        setData(dataState);
      }
```

**File:** packages/gui/src/components/offers/NFTOfferViewer.tsx (L467-491)
```typescript
              <NFTOfferSummary
                isMyOffer={isMyOffer}
                imported={!!imported}
                summary={summary}
                title={
                  <Typography variant="h6" style={{ fontWeight: 'bold' }}>
                    <Trans>Purchase Summary</Trans>
                  </Typography>
                }
                makerTitle={
                  <Typography variant="body1" color="textSecondary">
                    <Trans>You will receive</Trans>
                  </Typography>
                }
                takerTitle={
                  <Typography variant="body1" color="textSecondary">
                    <Trans>In exchange for</Trans>
                  </Typography>
                }
                setIsMissingRequestedAsset={(isMissing: boolean) => setIsMissingRequestedAsset(isMissing)}
                rowIndentation={0}
                showNFTPreview={false}
                showMakerFee={false}
                overrideNFTSellerAmount={overrideNFTSellerAmount}
              />
```
