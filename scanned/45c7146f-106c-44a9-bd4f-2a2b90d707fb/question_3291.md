# Q3291: nft-metadata via useNFTMinterDID 3291

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTMinterDID` (packages/gui/src/hooks/useNFTMinterDID.ts) control content hash/status fields that change across fetches with reordered RPC events and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMinterDID.ts` / `useNFTMinterDID`
- Entrypoint: NFT preview dialog
- Attacker controls: content hash/status fields that change across fetches; with reordered RPC events
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
