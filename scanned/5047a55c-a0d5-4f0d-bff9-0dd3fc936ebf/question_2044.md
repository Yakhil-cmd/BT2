# Q2044: nft-metadata via NFTTitle 2044

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTTitle` (packages/gui/src/components/nfts/NFTTitle.tsx) control objectionable-content flags and hidden NFT state with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTTitle.tsx` / `NFTTitle`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with a duplicate identifier
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
