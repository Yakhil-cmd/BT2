# Q3704: nft-metadata via useHideObjectionableContent 3704

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useHideObjectionableContent` (packages/gui/src/hooks/useHideObjectionableContent.ts) control content hash/status fields that change across fetches with a delayed metadata fetch and drive the sequence import -> parse -> preview -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useHideObjectionableContent.ts` / `useHideObjectionableContent`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; with a delayed metadata fetch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
