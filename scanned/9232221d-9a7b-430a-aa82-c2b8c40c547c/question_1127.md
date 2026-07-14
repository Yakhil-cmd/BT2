# Q1127: nft-metadata via Search 1127

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `Search` (packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx) control content hash/status fields that change across fetches during a pending modal confirmation and drive the sequence connect -> approve -> switch context -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx` / `Search`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; during a pending modal confirmation
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
