# Q2871: nft-metadata via checkNFTOwnership 2871

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `checkNFTOwnership` (packages/gui/src/electron/api/checkNFTOwnership.ts) control filename and MIME/type mismatch during download with a duplicate identifier and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/checkNFTOwnership.ts` / `checkNFTOwnership`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: filename and MIME/type mismatch during download; with a duplicate identifier
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
