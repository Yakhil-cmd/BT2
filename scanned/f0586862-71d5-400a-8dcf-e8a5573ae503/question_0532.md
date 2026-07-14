# Q532: nft-metadata via useNFTCoinAdded 532

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useNFTCoinAdded` (packages/api-react/src/hooks/useNFTCoinAdded.ts) control HTML/SVG/media content rendered in preview with a cached permission entry and drive the sequence open notification -> resolve details -> execute so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api-react/src/hooks/useNFTCoinAdded.ts` / `useNFTCoinAdded`
- Entrypoint: external NFT link open action
- Attacker controls: HTML/SVG/media content rendered in preview; with a cached permission entry
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
