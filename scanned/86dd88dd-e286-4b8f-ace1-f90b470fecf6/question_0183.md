# Q183: nft-metadata via NFTs 183

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTs` (packages/gui/src/components/nfts/NFTs.tsx) control objectionable-content flags and hidden NFT state with case-normalized identifiers and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTs.tsx` / `NFTs`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with case-normalized identifiers
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
