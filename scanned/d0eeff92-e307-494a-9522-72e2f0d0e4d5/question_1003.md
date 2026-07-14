# Q1003: nft-metadata via checkNFTOwnership 1003

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `checkNFTOwnership` (packages/gui/src/electron/api/checkNFTOwnership.ts) control content hash/status fields that change across fetches after a failed RPC response and drive the sequence select -> edit backing object -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/checkNFTOwnership.ts` / `checkNFTOwnership`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; after a failed RPC response
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
