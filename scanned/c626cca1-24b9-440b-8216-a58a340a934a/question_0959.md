# Q959: nft-metadata via const 959

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `const` (packages/gui/src/components/nfts/provider/hooks/useNFTData.ts) control objectionable-content flags and hidden NFT state with reordered RPC events and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTData.ts` / `const`
- Entrypoint: on-demand NFT data provider
- Attacker controls: objectionable-content flags and hidden NFT state; with reordered RPC events
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
