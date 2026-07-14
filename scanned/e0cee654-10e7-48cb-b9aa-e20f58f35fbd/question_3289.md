# Q3289: nft-metadata via if 3289

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `if` (packages/gui/src/hooks/useNFTMetadataLRU.ts) control filename and MIME/type mismatch during download with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMetadataLRU.ts` / `if`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with a delayed metadata fetch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
