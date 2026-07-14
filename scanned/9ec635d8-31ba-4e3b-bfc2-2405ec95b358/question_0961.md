# Q961: nft-metadata via events 961

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `events` (packages/gui/src/components/nfts/provider/hooks/useNFTDataNachos.ts) control content hash/status fields that change across fetches with conflicting localStorage preferences and drive the sequence download or render content -> trigger linked wallet action so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/hooks/useNFTDataNachos.ts` / `events`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; with conflicting localStorage preferences
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
