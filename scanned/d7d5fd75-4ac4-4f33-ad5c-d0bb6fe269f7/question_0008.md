# Q8: nft-metadata via NFTWallet 8

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTWallet` (packages/api/src/wallets/NFT.ts) control content hash/status fields that change across fetches with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/wallets/NFT.ts` / `NFTWallet`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; with a cached permission entry
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
