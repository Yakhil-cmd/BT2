# Q955: nft-metadata via profilesLocal 955

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `profilesLocal` (packages/gui/src/components/nfts/NFTProfileDropdown.tsx) control content hash/status fields that change across fetches after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProfileDropdown.tsx` / `profilesLocal`
- Entrypoint: on-demand NFT data provider
- Attacker controls: content hash/status fields that change across fetches; after a failed RPC response
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
