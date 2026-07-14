# Q3907: nft-metadata via NFTProperty 3907

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTProperty` (packages/gui/src/components/nfts/NFTProperties.tsx) control filename and MIME/type mismatch during download with a delayed metadata fetch and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProperties.tsx` / `NFTProperty`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with a delayed metadata fetch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
