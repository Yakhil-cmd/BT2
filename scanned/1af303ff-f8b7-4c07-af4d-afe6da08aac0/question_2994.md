# Q2994: nft-metadata via Search 2994

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `Search` (packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx) control filename and MIME/type mismatch during download after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/NFTGallerySearch.tsx` / `Search`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; after a failed RPC response
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
