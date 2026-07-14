# Q2959: nft-metadata via disabled 2959

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `disabled` (packages/gui/src/components/nfts/NFTContextualActions.tsx) control objectionable-content flags and hidden NFT state with a delayed metadata fetch and drive the sequence open notification -> resolve details -> execute so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTContextualActions.tsx` / `disabled`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: objectionable-content flags and hidden NFT state; with a delayed metadata fetch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
