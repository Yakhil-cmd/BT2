# Q1098: nft-metadata via ModelExtension 1098

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `ModelExtension` (packages/gui/src/components/nfts/NFTPreview.tsx) control objectionable-content flags and hidden NFT state after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTPreview.tsx` / `ModelExtension`
- Entrypoint: on-demand NFT data provider
- Attacker controls: objectionable-content flags and hidden NFT state; after a network switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
