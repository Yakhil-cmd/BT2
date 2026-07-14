# Q3290: nft-metadata via useNFTMinterDID 3290

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `useNFTMinterDID` (packages/gui/src/hooks/useNFTMinterDID.ts) control content hash/status fields that change across fetches with reordered RPC events and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMinterDID.ts` / `useNFTMinterDID`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: content hash/status fields that change across fetches; with reordered RPC events
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
