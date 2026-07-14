# Q175: nft-metadata via NFTSummary 175

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `NFTSummary` (packages/gui/src/components/nfts/NFTSummary.tsx) control filename and MIME/type mismatch during download with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTSummary.tsx` / `NFTSummary`
- Entrypoint: NFT preview dialog
- Attacker controls: filename and MIME/type mismatch during download; with a redirected remote resource
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
