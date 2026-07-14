# Q1442: nft-metadata via getNFTFileType 1442

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `getNFTFileType` (packages/gui/src/util/getNFTFileType.ts) control objectionable-content flags and hidden NFT state with conflicting localStorage preferences and drive the sequence select -> edit backing object -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTFileType.ts` / `getNFTFileType`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: objectionable-content flags and hidden NFT state; with conflicting localStorage preferences
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
