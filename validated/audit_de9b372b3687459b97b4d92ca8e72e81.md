### Title
NFT "Download" Action Bypasses On-Chain Hash Verification, Enabling Delivery of Malicious Files to User Filesystem - (File: packages/gui/src/components/nfts/NFTContextualActions.tsx)

### Summary
The Chia GUI NFT download feature fetches and saves NFT data files to the user's local filesystem using only the raw `dataUris[0]` URL from on-chain state, without verifying the downloaded content against the on-chain `dataHash`. An attacker who mints or controls an NFT can serve malicious content (e.g., a PDF with embedded exploits, a disguised executable) from the data URI. When a victim clicks "Download," the malicious file is written to their disk with no integrity check, bypassing the hash-verification system that exists elsewhere in the codebase.

### Finding Description

The Chia NFT standard commits both a `dataUris` list and a `dataHash` on-chain. The GUI's `useNFTVerifyHash` hook exists precisely to compare the SHA-256 of fetched content against `dataHash` before trusting it. This verification is used for in-app preview rendering. However, the "Download" action in `NFTDownloadContextualAction` completely skips this step.

**Single-file download path** (`handleDownload`, lines 409–415):

```ts
const dataUrlLocal = first.dataUris?.[0];
if (dataUrlLocal) {
  download(dataUrlLocal);   // no hash check
}
```

`download()` calls `window.appAPI.download(url)`, which triggers `mainWindow.webContents.downloadURL(urlLocal)` in the Electron main process — writing whatever the remote server returns to the user's Downloads folder. [1](#0-0) [2](#0-1) 

**Multi-file download path** (`startMultipleDownload`, lines 586–618):

```ts
const url = nft.dataUris[0];
// ...
await downloadFile(downloadUrl, filePath, { ... });  // no hash check
```

Again, `downloadFile` fetches and writes the remote content to disk with no comparison against `nft.dataHash`. [3](#0-2) 

By contrast, the preview path in `useNFTVerifyHash` does perform the check:

```ts
const checksum = await getChecksum(uri, { ... });
const isValid = compareChecksums(checksum, hash);
``` [4](#0-3) 

The download action never calls `useNFTVerifyHash` or any equivalent before saving the file. [5](#0-4) 

### Impact Explanation

An attacker mints an NFT whose `dataUris[0]` points to an attacker-controlled server. The server initially serves a benign file (so the on-chain `dataHash` matches). After minting, the server begins serving a malicious file (e.g., a PDF with a known exploit, a disguised `.exe`). Any wallet user who clicks "Download" on this NFT receives the malicious file on their local filesystem. If the user opens it, it can execute arbitrary code in the context of their OS session — where the Chia wallet keyring, mnemonic backup files, and config files reside — enabling direct theft of wallet secrets and funds.

This meets the allowed High impact: **"Unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content that produces direct asset loss, approval hijack, persistent lockout, or other concrete wallet security impact."** [6](#0-5) 

### Likelihood Explanation

- The attacker only needs to mint one NFT (or transfer one to a victim) — no privileged access required.
- The attack is silent: the "Download" menu item appears for any NFT with a `dataUris` entry; there is no hash-mismatch warning before saving.
- The `NFTHashStatus` chip (shown in the preview UI) only reflects the cached preview state, not the download action, so a user may see "Hash matches" in the preview while downloading tampered content.
- The user must click "Download" and then open the file, which is a realistic action for NFT owners who want to preserve their assets locally. [7](#0-6) [8](#0-7) 

### Recommendation

Before initiating any download, resolve the file from the cache layer (which already computes the SHA-256 checksum during `fetchRemoteContent`) and compare it against `nft.dataHash`. If the hashes do not match, abort the download and display a warning dialog. Concretely:

1. Call `getChecksum(dataUri)` (already available via `useCache`) and compare against `nft.dataHash` using `compareChecksums`.
2. If verification fails, show a blocking dialog ("Content does not match the on-chain hash — download aborted").
3. If verification passes, proceed with saving the already-cached file rather than re-fetching from the remote URL. [9](#0-8) [10](#0-9) 

### Proof of Concept

1. Attacker mints an NFT with `dataUris = ["https://attacker.example/nft.pdf"]` and `dataHash = sha256(benign_pdf)`. The server initially serves `benign_pdf`.
2. Attacker transfers the NFT to a victim wallet (or lists it for sale; victim purchases it).
3. Attacker's server begins serving `malicious.pdf` (e.g., a PDF embedding CVE-2018-4993 or similar) at the same URL.
4. Victim opens Chia GUI, navigates to their NFT gallery, right-clicks the NFT → "Download."
5. `NFTDownloadContextualAction.handleDownload()` reads `nft.dataUris[0]` = `"https://attacker.example/nft.pdf"` and calls `download(dataUrlLocal)` with no hash check.
6. Electron's `mainWindow.webContents.downloadURL(url)` fetches and saves `malicious.pdf` to the victim's Downloads folder.
7. Victim opens the file; malicious payload executes; attacker obtains access to the OS session where Chia wallet keys are stored. [11](#0-10) [2](#0-1)

### Citations

**File:** packages/gui/src/components/nfts/NFTContextualActions.tsx (L394-465)
```typescript
function NFTDownloadContextualAction(props: NFTDownloadContextualActionProps) {
  const { selection } = props;

  const selectedNfts: (NFTInfo & { $nftId: string })[] = selection?.items || [];

  const openDialog = useOpenDialog();
  const [, setSelectedNFTIds] = useLocalStorage('gallery-selected-nfts', []);

  const downloadable = selectedNfts.filter((nft) => !!nft.dataUris?.length);

  async function handleDownload() {
    if (!downloadable.length) {
      return;
    }

    if (downloadable.length === 1) {
      const [first] = downloadable;
      const dataUrlLocal = first.dataUris?.[0];
      if (dataUrlLocal) {
        download(dataUrlLocal);
      }
      return;
    }

    setSelectedNFTIds([]);

    try {
      const tasks: { url: string; filename: string }[] = selectedNfts.map((nft) => {
        const url = nft.dataUris[0];
        if (!url) {
          throw new Error('No data URI found for NFT');
        }

        const nftId = nft.$nftId || toBech32m(nft.launcherId, 'nft');

        const ext = getFileExtension(url);
        const filename = ext ? `${nftId}.${ext}` : nftId;

        return {
          url,
          filename,
        };
      });

      const selectedFolder = await window.appAPI.startMultipleDownload(tasks);
      if (selectedFolder) {
        await openDialog(<MultipleDownloadDialog folder={selectedFolder} />);
      }
    } catch (error) {
      openDialog(
        <AlertDialog title={<Trans>Download Failed</Trans>}>
          <Trans>The download failed: {error?.message || 'Unknown error'}</Trans>
        </AlertDialog>,
      );
    }
  }

  if (!downloadable.length) {
    return null;
  }

  return (
    <MenuItem onClick={handleDownload} disabled={!downloadable.length} close>
      <ListItemIcon>
        <DownloadIcon />
      </ListItemIcon>
      <Typography variant="inherit" noWrap>
        <Trans>Download</Trans>
      </Typography>
    </MenuItem>
  );
}
```

**File:** packages/gui/src/electron/main.tsx (L547-558)
```typescript
    ipcMainHandle(AppAPI.DOWNLOAD, async (urlLocal: string) => {
      if (!isValidURL(urlLocal)) {
        return;
      }

      if (!mainWindow) {
        console.error('mainWindow was not initialized');
        return;
      }

      mainWindow.webContents.downloadURL(urlLocal);
    });
```

**File:** packages/gui/src/electron/main.tsx (L586-618)
```typescript
      for (let i = 0; i < tasks.length; i++) {
        const { url: downloadUrl, filename } = tasks[i];

        try {
          if (!isValidURL(downloadUrl)) {
            throw new Error('Invalid URL');
          }

          const sanitizedFilename = sanitizeFilename(filename);
          if (sanitizedFilename !== filename) {
            throw new Error(
              `Filename ${filename} contains invalid characters. Filename sanitized to ${sanitizedFilename}`,
            );
          }

          const filePath = path.join(folder, sanitizedFilename);

          await downloadFile(downloadUrl, filePath, {
            onProgress: (progress) => handleDownloadProgress(progress, downloadUrl, i, tasks.length),
          });

          const fileStats = await fs.promises.stat(filePath);

          totalDownloadedSize += fileStats.size;
          successFileCount++;
        } catch (e: any) {
          if (e.message === 'download aborted' && abortDownloadingFiles) {
            break;
          }
          mainWindow?.webContents.send(AppAPI.ON_ERROR_DOWNLOADING_URL, downloadUrl);
          errorFileCount++;
        }
      }
```

**File:** packages/gui/src/hooks/useNFTVerifyHash.ts (L57-72)
```typescript
      for (const uri of urisToCheck) {
        try {
          // eslint-disable-next-line no-await-in-loop -- we need sync version
          const checksum = await getChecksum(uri, {
            maxSize: ignoreSizeLimit ? -1 : undefined,
          });

          const isValid = compareChecksums(checksum, hash);
          if (isValid) {
            return {
              isVerified: true,
              uri,
            };
          }

          throw new Error('Invalid hash checksum');
```

**File:** packages/gui/src/util/download.ts (L1-3)
```typescript
export default async function download(url: string): Promise<void> {
  return window.appAPI.download(url);
}
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

**File:** packages/gui/src/hooks/useFetchAndProcessMetadata.ts (L20-25)
```typescript
      const checksum = await getChecksum(uri);

      log(`Comparing checksums ${checksum} and ${hash}`);
      if (hash && !compareChecksums(checksum, hash)) {
        throw new Error('Checksum mismatch');
      }
```

**File:** packages/gui/src/electron/CacheManager.ts (L461-487)
```typescript
  async getChecksum(
    url: string,
    options?: {
      maxSize?: number;
      timeout?: number;
    },
  ): Promise<string> {
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
      return cacheInfo.checksum;
    }

    throw new Error('Unknown cache state');
  }
```
