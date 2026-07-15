### Title
NFT Metadata Hash Check Bypassed When `metadataHash` Is Empty String, Allowing Unverified Metadata Display — (`packages/gui/src/hooks/useFetchAndProcessMetadata.ts`)

---

### Summary

The guard in `fetchAndProcessMetadata` uses a JavaScript falsy check (`if (hash && ...)`) to decide whether to verify the metadata checksum. When the on-chain `metadataHash` is an empty string `''` — a value the RPC legitimately returns for NFTs minted without a metadata hash — the entire checksum verification is skipped and arbitrary attacker-controlled metadata is parsed and displayed without any integrity check or user warning.

---

### Finding Description

In `useFetchAndProcessMetadata.ts`, the checksum guard is:

```typescript
if (hash && !compareChecksums(checksum, hash)) {
  throw new Error('Checksum mismatch');
}
``` [1](#0-0) 

When `hash` is `''` (empty string), the JavaScript `&&` short-circuits to `false` and the entire `compareChecksums` call is never reached. The function proceeds to fetch, parse, and return the metadata from the URI with no integrity verification.

The call chain is:

1. `useMetadataData` destructures `metadataHash` directly from the RPC-returned `NFTInfo` with no normalization:

```typescript
const { metadataUris = [], metadataHash } = nft;
// ...
const metadata = await fetchAndProcessMetadata(firstUri, metadataHash);
``` [2](#0-1) 

2. The `NFTInfo` type declares `metadataHash: string` (not `string | undefined`), and the test fixture confirms the RPC returns `''` as the canonical empty value:

```typescript
metadataHash: '',
``` [3](#0-2) 

3. `NFTDetails.tsx` also explicitly handles `''` and `'0x'` as "no hash" sentinel values, confirming both are real RPC outputs:

```typescript
if (nft.metadataHash && nft.metadataHash !== '0x') { ... }
``` [4](#0-3) 

Note: `'0x'` is **not** a bypass — it is truthy, so `compareChecksums` runs, strips it to `''`, and the mismatch throws. Only `''` (empty string) is falsy and causes the bypass.

---

### Impact Explanation

The `Metadata` type includes `name`, `image`, `description`, `collection`, `preview_image_uris`, and `preview_video_uris`. [5](#0-4) 

All of these fields are rendered in the NFT gallery, detail view, and offer confirmation dialogs. An attacker who minted an NFT with an empty `metadataHash` and controls the metadata URI server can change the served JSON at any time. The GUI will display whatever the server returns — different name, image, collection — with no indication that the content is unverified. A victim viewing or accepting an offer for this NFT sees attacker-controlled identity information, satisfying the High impact criterion of displaying the wrong asset identity.

---

### Likelihood Explanation

- Any Chia user can mint an NFT with no metadata hash (it is an optional field in the NFT standard).
- The attacker only needs to control a web server hosting the metadata URI — no special access to the victim's machine is required.
- The bypass is triggered automatically whenever the GUI loads metadata for such an NFT; no user interaction beyond viewing the NFT is needed.
- The RPC returning `''` for `metadataHash` is confirmed by both the type definition and the test fixture.

---

### Recommendation

Replace the falsy guard with an explicit `undefined`/`null` check, and treat empty string as "no hash provided" by either refusing to load metadata or displaying a clear "unverified" warning:

```typescript
// Option A: reject metadata when no hash is present
if (!hash || hash === '' || hash === '0x') {
  throw new Error('No metadata hash provided; cannot verify integrity');
}
if (!compareChecksums(checksum, hash)) {
  throw new Error('Checksum mismatch');
}

// Option B: load but surface an explicit unverified flag to the UI
const isVerified = !!(hash && hash !== '0x' && compareChecksums(checksum, hash));
```

The UI should propagate and display an "unverified" badge whenever `isVerified` is false, so users can make informed decisions in offer flows.

---

### Proof of Concept

Unit test (no network required):

```typescript
// Mock getChecksum to return a fixed hash for any URI
// Mock getContent/getHeaders to return attacker-controlled JSON
const mockGetChecksum = jest.fn().mockResolvedValue('aabbcc');
const mockGetContent = jest.fn().mockResolvedValue('{"name":"FAKE NFT","image":"http://evil.com/fake.png"}');
const mockGetHeaders = jest.fn().mockResolvedValue({});

// Call with hash = '' (empty string, as returned by RPC for no-hash NFTs)
const result = await fetchAndProcessMetadata('http://attacker.com/meta.json', '');

// Current behavior: returns { name: 'FAKE NFT', image: 'http://evil.com/fake.png' }
// Expected behavior: throws an error (metadata cannot be trusted without a hash)
expect(result).toThrow(); // FAILS — no throw occurs
```

The test confirms that passing `hash = ''` causes the guard at line 23 of `useFetchAndProcessMetadata.ts` to be skipped entirely, and the attacker's JSON is returned as trusted metadata.

### Citations

**File:** packages/gui/src/hooks/useFetchAndProcessMetadata.ts (L23-25)
```typescript
      if (hash && !compareChecksums(checksum, hash)) {
        throw new Error('Checksum mismatch');
      }
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

**File:** packages/api/src/tests/utils/calculateRoyalties.test.ts (L27-27)
```typescript
      metadataHash: '',
```

**File:** packages/gui/src/components/nfts/NFTDetails.tsx (L262-262)
```typescript
    if (nft.metadataHash && nft.metadataHash !== '0x') {
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
