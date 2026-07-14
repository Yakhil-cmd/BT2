# Q1092: nft-metadata via details 1092

## Question
Can an unprivileged attacker entering through the external NFT link open action in `details` (packages/gui/src/components/nfts/NFTDetails.tsx) control metadata URI list with mixed schemes and redirects after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTDetails.tsx` / `details`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; after a network switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
