# Q1599: nft-metadata via if 1599

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `if` (packages/gui/src/hooks/useNFTGalleryScrollPosition.ts) control objectionable-content flags and hidden NFT state with a duplicate identifier and drive the sequence select -> edit backing object -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTGalleryScrollPosition.ts` / `if`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; with a duplicate identifier
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
