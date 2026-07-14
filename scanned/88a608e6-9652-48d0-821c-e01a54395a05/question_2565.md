# Q2565: nft-metadata via getNFTId 2565

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `getNFTId` (packages/gui/src/util/getNFTId.ts) control HTML/SVG/media content rendered in preview with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTId.ts` / `getNFTId`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; with conflicting localStorage preferences
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
