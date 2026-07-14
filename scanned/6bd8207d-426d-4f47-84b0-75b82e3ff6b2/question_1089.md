# Q1089: nft-metadata via nftId 1089

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `nftId` (packages/gui/src/components/nfts/NFTCard.tsx) control HTML/SVG/media content rendered in preview with a redirected remote resource and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTCard.tsx` / `nftId`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; with a redirected remote resource
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
