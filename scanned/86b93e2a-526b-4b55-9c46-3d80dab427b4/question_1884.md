# Q1884: nft-metadata via NFTMetadata 1884

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTMetadata` (packages/gui/src/components/nfts/NFTMetadata.tsx) control filename and MIME/type mismatch during download after canceling and reopening the dialog and drive the sequence open notification -> resolve details -> execute so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTMetadata.tsx` / `NFTMetadata`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; after canceling and reopening the dialog
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
