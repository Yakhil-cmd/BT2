# Q161: nft-metadata via NFTFilterProvider 161

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTFilterProvider` (packages/gui/src/components/nfts/NFTFilterProvider.tsx) control metadata URI list with mixed schemes and redirects with reordered RPC events and drive the sequence download or render content -> trigger linked wallet action so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTFilterProvider.tsx` / `NFTFilterProvider`
- Entrypoint: on-demand NFT data provider
- Attacker controls: metadata URI list with mixed schemes and redirects; with reordered RPC events
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
