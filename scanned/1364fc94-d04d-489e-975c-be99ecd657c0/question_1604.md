# Q1604: nft-metadata via nachoNFTIDs 1604

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `nachoNFTIDs` (packages/gui/src/hooks/useNachoNFTs.ts) control metadata URI list with mixed schemes and redirects with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNachoNFTs.ts` / `nachoNFTIDs`
- Entrypoint: NFT preview dialog
- Attacker controls: metadata URI list with mixed schemes and redirects; with precision-boundary values
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
