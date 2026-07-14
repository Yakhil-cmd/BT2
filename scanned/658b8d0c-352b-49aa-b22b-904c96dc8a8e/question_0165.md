# Q165: nft-metadata via StyledCardPreview 165

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `StyledCardPreview` (packages/gui/src/components/nfts/NFTPreview.tsx) control content hash/status fields that change across fetches after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTPreview.tsx` / `StyledCardPreview`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; after a failed RPC response
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
