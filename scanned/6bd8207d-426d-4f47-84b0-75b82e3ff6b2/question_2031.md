# Q2031: nft-metadata via icon 2031

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `icon` (packages/gui/src/components/nfts/NFTHashStatus.tsx) control metadata URI list with mixed schemes and redirects with conflicting localStorage preferences and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTHashStatus.tsx` / `icon`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: metadata URI list with mixed schemes and redirects; with conflicting localStorage preferences
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
