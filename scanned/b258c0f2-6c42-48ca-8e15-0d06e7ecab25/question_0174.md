# Q174: nft-metadata via NFTSummary 174

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `NFTSummary` (packages/gui/src/components/nfts/NFTSummary.tsx) control HTML/SVG/media content rendered in preview with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTSummary.tsx` / `NFTSummary`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: HTML/SVG/media content rendered in preview; with a redirected remote resource
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
