# Q1877: nft-metadata via getNfts 1877

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `getNfts` (packages/api/src/wallets/NFT.ts) control HTML/SVG/media content rendered in preview with case-normalized identifiers and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/wallets/NFT.ts` / `getNfts`
- Entrypoint: multiple NFT download action
- Attacker controls: HTML/SVG/media content rendered in preview; with case-normalized identifiers
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
