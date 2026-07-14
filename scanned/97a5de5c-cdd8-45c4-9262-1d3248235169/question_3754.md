# Q3754: nft-metadata via handleProfileSelected 3754

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `handleProfileSelected` (packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx) control HTML/SVG/media content rendered in preview with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx` / `handleProfileSelected`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; with a stale Redux cache
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
