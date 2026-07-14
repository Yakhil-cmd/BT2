# Q2924: nft-metadata via convertRoyaltyToPercentage 2924

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `convertRoyaltyToPercentage` (packages/gui/src/util/nfts.ts) control metadata URI list with mixed schemes and redirects with a duplicate identifier and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/nfts.ts` / `convertRoyaltyToPercentage`
- Entrypoint: multiple NFT download action
- Attacker controls: metadata URI list with mixed schemes and redirects; with a duplicate identifier
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
