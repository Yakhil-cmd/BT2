# Q1623: nft-metadata via getSpacescanURL 1623

## Question
Can an unprivileged attacker entering through the external NFT link open action in `getSpacescanURL` (packages/gui/src/hooks/useViewNFTOnExplorer.ts) control metadata URI list with mixed schemes and redirects after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useViewNFTOnExplorer.ts` / `getSpacescanURL`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; after a profile switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
