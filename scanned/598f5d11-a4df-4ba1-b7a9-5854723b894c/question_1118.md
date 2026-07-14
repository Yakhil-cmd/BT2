# Q1118: nft-metadata via if 1118

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `if` (packages/gui/src/components/nfts/detail/NFTDetailV2.tsx) control objectionable-content flags and hidden NFT state through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/detail/NFTDetailV2.tsx` / `if`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; through a batch of rapid user-accessible actions
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
