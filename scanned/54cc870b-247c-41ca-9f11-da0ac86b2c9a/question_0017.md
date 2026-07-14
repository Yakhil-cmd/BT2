# Q17: nft-metadata via NFTMetadata 17

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTMetadata` (packages/gui/src/components/nfts/NFTMetadata.tsx) control content hash/status fields that change across fetches after a profile switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTMetadata.tsx` / `NFTMetadata`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; after a profile switch
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
