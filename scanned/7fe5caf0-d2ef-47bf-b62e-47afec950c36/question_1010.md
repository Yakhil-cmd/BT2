# Q1010: nft-metadata via nftGetInfo 1010

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `nftGetInfo` (packages/gui/src/electron/api/nftGetInfo.ts) control content hash/status fields that change across fetches with a duplicate identifier and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/nftGetInfo.ts` / `nftGetInfo`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; with a duplicate identifier
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
