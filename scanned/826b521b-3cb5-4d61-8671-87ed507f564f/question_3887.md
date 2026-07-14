# Q3887: nft-metadata via handleClose 3887

## Question
Can an unprivileged attacker entering through the external NFT link open action in `handleClose` (packages/gui/src/components/nfts/NFTAutocomplete.tsx) control content hash/status fields that change across fetches with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTAutocomplete.tsx` / `handleClose`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with a delayed metadata fetch
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
