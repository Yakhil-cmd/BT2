# Q1888: nft-metadata via NFTProfileDropdown 1888

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTProfileDropdown` (packages/gui/src/components/nfts/NFTProfileDropdown.tsx) control HTML/SVG/media content rendered in preview after a network switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProfileDropdown.tsx` / `NFTProfileDropdown`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; after a network switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
