# Q3761: nft-metadata via fetchLimited 3761

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `fetchLimited` (packages/gui/src/components/nfts/provider/hooks/useNFTData.ts) control metadata URI list with mixed schemes and redirects after a network switch and drive the sequence import -> parse -> preview -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTData.ts` / `fetchLimited`
- Entrypoint: NFT preview dialog
- Attacker controls: metadata URI list with mixed schemes and redirects; after a network switch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: rendered, downloaded, and approved NFT data must match verified hashes, canonical IDs, safe schemes, and selected wallet/DID context
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
