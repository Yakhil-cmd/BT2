# Q2561: nft-metadata via download 2561

## Question
Can an unprivileged attacker entering through the external NFT link open action in `download` (packages/gui/src/util/download.ts) control content hash/status fields that change across fetches with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would make remote metadata appear verified for different content than the rendered or downloaded asset, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/download.ts` / `download`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with case-normalized identifiers
- Exploit idea: make remote metadata appear verified for different content than the rendered or downloaded asset
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
