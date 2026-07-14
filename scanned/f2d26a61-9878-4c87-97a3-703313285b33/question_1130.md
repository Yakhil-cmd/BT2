# Q1130: nft-metadata via NFTProviderContext 1130

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTProviderContext` (packages/gui/src/components/nfts/provider/NFTProviderContext.ts) control objectionable-content flags and hidden NFT state with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProviderContext.ts` / `NFTProviderContext`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; with a delayed metadata fetch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
