# Q1093: nft-metadata via details 1093

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `details` (packages/gui/src/components/nfts/NFTDetails.tsx) control content hash/status fields that change across fetches after a network switch and drive the sequence import -> parse -> preview -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTDetails.tsx` / `details`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; after a network switch
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
