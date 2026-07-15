### Title
NFT Content Spoofing via MD5 Collision in `getCacheFilePath` Allows Verified Display of Wrong NFT Asset — (`packages/gui/src/electron/CacheManager.ts`)

### Summary

`getCacheFilePath` uses MD5 to derive the on-disk filename for cached NFT content. Because MD5 is collision-broken and `getCacheInfo` never validates that the stored `url` field in the info file matches the requested URL, an attacker who can craft two NFT data URIs with the same MD5 hash can cause NFT-B to be served NFT-A's cached content and pass the SHA256 hash verification, displaying the wrong asset as "verified."

---

### Finding Description

`getCacheFilePath` derives the cache filename solely from `MD5(url)`: [1](#0-0) 

The companion info file (written by `setCacheInfo`) stores `{ url, state, checksum, headers, timestamp }` at `{MD5(url)}-chiacache-info`: [2](#0-1) 

When `getCacheInfo` reads the info file it returns the raw parsed JSON **without checking that the stored `url` field matches the URL that was requested**: [3](#0-2) 

`fetchRemoteContent` then short-circuits on `state === CACHED` and returns the colliding info object: [4](#0-3) 

`getChecksum` returns the `checksum` field from that info object (SHA256 of NFT-A's content) for NFT-B's URL: [5](#0-4) 

`useNFTVerifyHash` then compares that checksum against NFT-B's on-chain `data_hash`: [6](#0-5) 

`compareChecksums` is a plain string equality check with no additional protection: [7](#0-6) 

---

### Impact Explanation

An attacker who mints NFT-B can:

1. Craft `urlB` such that `MD5(urlB) = MD5(urlA)` for any existing NFT-A's `urlA` (MD5 chosen-prefix collisions are publicly documented and feasible).
2. Set NFT-B's on-chain `data_hash = SHA256(contentA)` at mint time (the attacker controls this field).
3. Wait for the victim to have cached NFT-A (or arrange for it to be cached first).
4. When the victim views NFT-B: `getCacheInfoByURL(urlB)` reads NFT-A's info file → returns `checksum = SHA256(contentA)` → `compareChecksums(SHA256(contentA), SHA256(contentA))` passes → NFT-B is displayed with NFT-A's content and marked **verified**.

`getContent(urlB)` also reads the same colliding file, so the rendered image/video is NFT-A's content: [8](#0-7) 

This causes the user to display the wrong asset with a verified badge — a spoofing impact within the defined High scope.

---

### Likelihood Explanation

- MD5 collision attacks (chosen-prefix) are well-documented and require no secret material.
- The attacker fully controls both the NFT data URIs and the on-chain `data_hash` at mint time.
- The only ordering constraint (NFT-A cached before NFT-B is viewed) is realistic: popular NFTs are cached by many users before a malicious NFT-B is encountered.
- No local host compromise, leaked keys, or social engineering is required.

---

### Recommendation

1. **Replace MD5 with SHA256** in `getCacheFilePath` for file naming. SHA256 is already imported and used for content checksums.
2. **Add a URL binding check** in `getCacheInfo` or `getCacheInfoByURL`: after reading the info file, assert `cacheInfo.url === url` and treat a mismatch as `NOT_CACHED`, forcing a fresh download.
3. Alternatively, store the URL as part of the filename (URL-safe encoding or SHA256 of the URL) so collisions are computationally infeasible.

---

### Proof of Concept

```
1. Find/generate urlA and urlB with MD5(urlA) = MD5(urlB)
   (use any published MD5 chosen-prefix collision tool; embed collision
    bytes in the URL path, e.g. https://attacker.com/nft/<collision-bytes-A>
    and https://attacker.com/nft/<collision-bytes-B>)

2. Host contentA at urlA.

3. Mint NFT-A: data_uris=[urlA], data_hash=SHA256(contentA)

4. Mint NFT-B: data_uris=[urlB], data_hash=SHA256(contentA)
   (same hash as NFT-A's content — attacker sets this freely at mint)

5. Victim views NFT-A → CacheManager downloads contentA,
   writes {MD5(urlA)}-chiacache and {MD5(urlA)}-chiacache-info
   with checksum=SHA256(contentA).

6. Victim views NFT-B → getCacheFilePath(urlB) = same path as step 5
   → getCacheInfoByURL returns state=CACHED, checksum=SHA256(contentA)
   → fetchRemoteContent returns early (no download of urlB)
   → getChecksum(urlB) returns SHA256(contentA)
   → compareChecksums(SHA256(contentA), SHA256(contentA)) = true
   → NFT-B renders contentA with isVerified=true
```

### Citations

**File:** packages/gui/src/electron/CacheManager.ts (L228-230)
```typescript
    const urlHash = crypto.createHash('md5').update(url).digest('hex');
    const fileName = `${urlHash}${FILE_SUFFIX}`;
    return path.join(this.cacheDirectory, fileName);
```

**File:** packages/gui/src/electron/CacheManager.ts (L239-260)
```typescript
  private async getCacheInfo(filePath: string, url: string): Promise<CacheInfo> {
    try {
      const infoString = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(infoString) as CacheInfo;
    } catch (error) {
      const currentError = (error as Error) ?? new Error('Unknown error');
      if ((currentError as { code?: string }).code === 'ENOENT') {
        return {
          url,
          state: CacheState.NOT_CACHED,
          timestamp: Date.now(),
        };
      }

      return {
        url,
        state: CacheState.ERROR,
        error: currentError.message,
        timestamp: Date.now(),
      };
    }
  }
```

**File:** packages/gui/src/electron/CacheManager.ts (L268-279)
```typescript
  private async setCacheInfo(url: string, infoBase: CacheInfoBase) {
    const infoFilePath = this.getCacheInfoFilePath(url);

    const cacheInfo: CacheInfo = {
      ...infoBase,
      url,
      timestamp: Date.now(),
    };

    await fs.writeFile(infoFilePath, JSON.stringify(cacheInfo), 'utf-8');

    return cacheInfo;
```

**File:** packages/gui/src/electron/CacheManager.ts (L327-331)
```typescript
        const cacheInfo = await this.getCacheInfoByURL(url);
        if (cacheInfo.state === CacheState.CACHED) {
          log('Url already downloaded', url);
          return cacheInfo;
        }
```

**File:** packages/gui/src/electron/CacheManager.ts (L453-456)
```typescript
    if (cacheInfo.state === CacheState.CACHED) {
      const filePath = this.getCacheFilePath(url);
      return fs.readFile(filePath);
    }
```

**File:** packages/gui/src/electron/CacheManager.ts (L482-484)
```typescript
    if (cacheInfo.state === CacheState.CACHED) {
      return cacheInfo.checksum;
    }
```

**File:** packages/gui/src/hooks/useNFTVerifyHash.ts (L60-69)
```typescript
          const checksum = await getChecksum(uri, {
            maxSize: ignoreSizeLimit ? -1 : undefined,
          });

          const isValid = compareChecksums(checksum, hash);
          if (isValid) {
            return {
              isVerified: true,
              uri,
            };
```

**File:** packages/gui/src/util/compareChecksums.ts (L3-9)
```typescript
export default function compareChecksums(checksum1: string, checksum2: string) {
  // Remove the "0x" prefix from the checksums
  const strippedChecksum1 = removeHexPrefix(checksum1);
  const strippedChecksum2 = removeHexPrefix(checksum2);

  // Compare the stripped checksums and return the result
  return strippedChecksum1 === strippedChecksum2;
```
