# Q663: nft-metadata via useNFTCoinEvents 663

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `useNFTCoinEvents` (packages/gui/src/hooks/useNFTCoinEvents.ts) control content hash/status fields that change across fetches with a duplicate identifier and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTCoinEvents.ts` / `useNFTCoinEvents`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; with a duplicate identifier
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
