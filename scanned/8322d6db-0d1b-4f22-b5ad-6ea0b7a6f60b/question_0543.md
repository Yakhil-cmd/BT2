# Q543: nft-metadata via DataLayerRootHash 543

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `DataLayerRootHash` (packages/api/src/@types/DataLayerRootHash.ts) control HTML/SVG/media content rendered in preview after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/DataLayerRootHash.ts` / `DataLayerRootHash`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; after a failed RPC response
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
