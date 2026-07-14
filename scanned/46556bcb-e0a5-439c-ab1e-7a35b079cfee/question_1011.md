# Q1011: nft-metadata via nftGetInfo 1011

## Question
Can an unprivileged attacker entering through the external NFT link open action in `nftGetInfo` (packages/gui/src/electron/api/nftGetInfo.ts) control content hash/status fields that change across fetches with a duplicate identifier and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/nftGetInfo.ts` / `nftGetInfo`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with a duplicate identifier
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
