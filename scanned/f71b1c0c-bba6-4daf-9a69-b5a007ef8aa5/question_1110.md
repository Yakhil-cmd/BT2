# Q1110: nft-metadata via NFTTitle 1110

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTTitle` (packages/gui/src/components/nfts/NFTTitle.tsx) control HTML/SVG/media content rendered in preview after a profile switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTitle.tsx` / `NFTTitle`
- Entrypoint: on-demand NFT data provider
- Attacker controls: HTML/SVG/media content rendered in preview; after a profile switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
