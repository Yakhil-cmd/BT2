# Q2038: nft-metadata via NFTProperties 2038

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTProperties` (packages/gui/src/components/nfts/NFTProperties.tsx) control HTML/SVG/media content rendered in preview after canceling and reopening the dialog and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProperties.tsx` / `NFTProperties`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; after canceling and reopening the dialog
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
