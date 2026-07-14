# Q2355: nft-metadata via useNFTMetadataLRU 2355

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `useNFTMetadataLRU` (packages/gui/src/hooks/useNFTMetadataLRU.ts) control content hash/status fields that change across fetches after a profile switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTMetadataLRU.ts` / `useNFTMetadataLRU`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; after a profile switch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
