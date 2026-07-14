# Q588: nft-metadata via SigningEntityNFT 588

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `SigningEntityNFT` (packages/gui/src/components/signVerify/SigningEntityNFT.tsx) control content hash/status fields that change across fetches with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityNFT.tsx` / `SigningEntityNFT`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; with a stale Redux cache
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
