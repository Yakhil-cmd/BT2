# Q3813: nft-metadata via nftGetInfo 3813

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `nftGetInfo` (packages/gui/src/electron/api/nftGetInfo.ts) control metadata URI list with mixed schemes and redirects with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/nftGetInfo.ts` / `nftGetInfo`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: metadata URI list with mixed schemes and redirects; with a delayed metadata fetch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
