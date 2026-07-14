# Q1632: nft-metadata via getNFTsDataStatistics 1632

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `getNFTsDataStatistics` (packages/gui/src/util/getNFTsDataStatistics.ts) control objectionable-content flags and hidden NFT state after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/getNFTsDataStatistics.ts` / `getNFTsDataStatistics`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; after a network switch
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
